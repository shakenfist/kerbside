# Offline verification of Shaken Fist VDI console tokens.
#
# Shaken Fist mints an Ed25519-signed JWT (phase 2) and hands a viewer an
# exchange URL (<KERBSIDE_URL>/sf-console.vv?token=<jwt>). This module
# validates that JWT *entirely offline*: the signing public keys are cached
# in the kerbside DB by the shakenfist source (see sources/shakenfist.py),
# and verification reads them from there -- it never calls Shaken Fist on
# the hot path. The single exception is a cache miss on an unknown kid,
# which triggers exactly one refetch of every shakenfist source's keys via
# refresh_all_signing_keys() before giving up.
#
# SECURITY: the raw token string and any private material must never appear
# in a log line or an exception message. Public keys are fine to log.

import json

import jwt
import yaml
from shakenfist_utilities import logs

from .config import config
from . import db
from . import util


LOG, _ = logs.setup(__name__, **util.configure_logging())


class SfTokenError(Exception):
    """Base class for Shaken Fist console token verification failures."""


class Malformed(SfTokenError):
    """The token is not a well-formed EdDSA JWT."""


class UnknownKid(SfTokenError):
    """No cached signing key matches the token's kid, even after a refetch."""


class BadSignature(SfTokenError):
    """The token's kid is known but no candidate key verified its signature."""


class Expired(SfTokenError):
    """The token has expired."""


class WrongAudience(SfTokenError):
    """The token's audience does not match this kerbside deployment."""


# Sentinel returned by _verify_with_cached to mean "the token's kid is not
# present in any cached key set" -- distinct from a verification failure, so
# verify_sf_token can decide whether to refetch and retry.
_KID_UNKNOWN = None


def expected_audience():
    """The 'aud' claim value this kerbside deployment accepts.

    SF_CONSOLE_TOKEN_AUDIENCE overrides; empty derives it from PUBLIC_FQDN.
    Must equal Shaken Fist's KERBSIDE_URL.
    """
    if config.SF_CONSOLE_TOKEN_AUDIENCE:
        return config.SF_CONSOLE_TOKEN_AUDIENCE
    return 'https://%s' % config.PUBLIC_FQDN


def _shakenfist_source_names():
    """Names of every configured type == 'shakenfist' source."""
    names = []
    with open(config.SOURCES_PATH) as f:
        sources = yaml.safe_load(f) or []
        for source in sources:
            if source.get('type') != 'shakenfist':
                continue
            names.append(source['source'])
    return names


def _verify_with_cached(token, kid):
    """Verify a token against keys already cached in the DB.

    Returns the claim dict on success, raises a typed SfTokenError on a
    definitive rejection, or returns _KID_UNKNOWN when no cached key set
    contains the token's kid (so the caller may refetch and retry).
    """
    # Gather every (source_name, public_pem) whose cached key set contains a
    # key with the token's kid.
    candidates = []
    for source_name in _shakenfist_source_names():
        raw = db.get_sf_token_keys(source_name)
        if raw is None:
            continue
        try:
            cached = json.loads(raw)
        except (ValueError, TypeError):
            LOG.with_fields({'source': source_name}).warning(
                'Cached signing keys are not valid JSON; ignoring')
            continue
        for key in cached.get('keys', []):
            if key.get('kid') == kid:
                candidates.append((source_name, key.get('public_pem')))

    if not candidates:
        return _KID_UNKNOWN

    audience = expected_audience()
    for source_name, public_pem in candidates:
        try:
            payload = jwt.decode(
                token, public_pem, algorithms=['EdDSA'], audience=audience)
        except jwt.ExpiredSignatureError:
            # Definitive: the signature was valid but the token has expired.
            raise Expired('token has expired')
        except jwt.InvalidAudienceError:
            # Definitive: the signature was valid but the audience is wrong.
            raise WrongAudience('token audience is not accepted here')
        except jwt.InvalidSignatureError:
            # This key did not sign the token; try the next candidate.
            continue
        except jwt.PyJWTError:
            # Any other verification problem for this key; try the next one.
            continue

        return {
            'source': source_name,
            'sub': payload['sub'],
            'jti': payload['jti'],
            'exp': payload['exp'],
        }

    # The kid was known but no candidate key produced a valid signature.
    raise BadSignature('no cached key verified the token signature')


def verify_sf_token(token):
    """Verify a Shaken Fist VDI console token entirely offline.

    Returns {'source', 'sub', 'jti', 'exp'} on success. Raises a typed
    SfTokenError subclass on any rejection. The token string is never
    included in a log line or exception message.
    """
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError:
        raise Malformed('token header is not parseable')

    if header.get('alg') != 'EdDSA':
        raise Malformed('token algorithm is not EdDSA')
    kid = header.get('kid')

    result = _verify_with_cached(token, kid)
    if result is _KID_UNKNOWN:
        # Unknown kid: the signing key may have rotated. Refetch every
        # shakenfist source's keys once, then retry. This is the only path
        # in verification that touches Shaken Fist.
        LOG.with_fields({'kid': kid}).info(
            'Unknown signing kid; refetching keys once')
        refresh_all_signing_keys()
        result = _verify_with_cached(token, kid)
        if result is _KID_UNKNOWN:
            raise UnknownKid('no signing key matches the token kid')

    return result


def refresh_all_signing_keys():
    """Refetch and cache every shakenfist source's signing keys.

    Imported lazily to avoid an import cycle
    (sources.shakenfist -> db/config, and this module -> sources).
    """
    from .sources import shakenfist as shakenfist_source
    shakenfist_source.refresh_all_signing_keys()
