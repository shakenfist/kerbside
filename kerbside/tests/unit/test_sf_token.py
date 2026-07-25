# Adversarial matrix for kerbside.sf_token.verify_sf_token: valid, expired,
# wrong audience, forged signature, unknown kid (with and without a
# successful refetch), and malformed tokens. Mirrors the crypto-test style of
# Shaken Fist's shakenfist/tests/test_vdi_tokens.py -- a locally generated
# Ed25519 keypair signs real JWTs, verified entirely offline through the
# same sqlite-backed DB fixture style as test_db.py's SfTokenKeys/SfTokenJti
# cases, plus a temp sources.yaml (test_main.py's fixture style) so
# sf_token._shakenfist_source_names() finds the seeded source.

import json
import os
import tempfile
import time
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
import jwt
from sqlalchemy import create_engine
import testtools
import yaml

from kerbside import db
from kerbside import sf_token
from kerbside.config import config


SIGNING_ALG = 'EdDSA'


def _generate_keypair():
    """A fresh Ed25519 keypair as (private_pem, public_pem) strings.

    Mirrors shakenfist.util.vdi_tokens.generate_keypair()'s serialisation:
    unencrypted PKCS8 private PEM, SubjectPublicKeyInfo public PEM.
    """
    private_key = ed25519.Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode('utf-8')
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode('utf-8')
    return private_pem, public_pem


def _cached_keys_json(kid, public_pem):
    """The cached-keys JSON shape, matching Shaken Fist's public_view()."""
    return json.dumps({
        'active_kid': kid,
        'keys': [{
            'kid': kid,
            'alg': SIGNING_ALG,
            'public_pem': public_pem,
            'created': 0,
        }],
    })


class VerifySfTokenTestCase(testtools.TestCase):
    SOURCE_NAME = 'sf1'

    def setUp(self):
        super().setUp()

        # sqlite-backed sf_token_keys table, matching test_db.py's
        # SfTokenKeysDbTestCase fixture.
        self.engine = create_engine('sqlite://')
        db.Base.metadata.create_all(
            self.engine, tables=[db.SfTokenKeys.__table__])
        engine_patch = mock.patch.object(db, 'ENGINE', self.engine)
        engine_patch.start()
        self.addCleanup(engine_patch.stop)

        # A temp sources.yaml listing exactly the shakenfist source whose
        # keys we seed below, matching test_main.py's fixture style.
        sources_file = tempfile.NamedTemporaryFile(
            mode='w', suffix='.yaml', delete=False)
        yaml.dump([{
            'source': self.SOURCE_NAME,
            'type': 'shakenfist',
            'url': 'http://localhost:13000',
            'username': 'admin',
            'password': 'secret',
        }], sources_file)
        sources_file.close()
        self.addCleanup(os.unlink, sources_file.name)

        sources_patch = mock.patch.object(
            config, 'SOURCES_PATH', sources_file.name)
        sources_patch.start()
        self.addCleanup(sources_patch.stop)

        self.private_pem, self.public_pem = _generate_keypair()
        self.kid = 'kid-1'
        db.upsert_sf_token_keys(
            self.SOURCE_NAME,
            _cached_keys_json(self.kid, self.public_pem), time.time())

        self.audience = sf_token.expected_audience()

        # Reset the module-level refetch debounce so each test starts able to
        # refetch (see sf_token._REFETCH_COOLDOWN_SECONDS).
        sf_token._last_refetch_attempt = 0.0

    def _make_token(
            self, private_pem=None, kid=None, aud=None, exp=None,
            sub='console-uuid', jti='jti-1', alg=SIGNING_ALG):
        claims = {
            'sub': sub,
            'jti': jti,
            'aud': self.audience if aud is None else aud,
            'exp': int(time.time()) + 300 if exp is None else exp,
        }
        return jwt.encode(
            claims,
            self.private_pem if private_pem is None else private_pem,
            algorithm=alg,
            headers={'kid': self.kid if kid is None else kid})

    # --- 1. valid ------------------------------------------------------

    def test_valid_token_returns_claims(self):
        token = self._make_token()
        result = sf_token.verify_sf_token(token)
        self.assertEqual(
            {'source': self.SOURCE_NAME, 'sub': 'console-uuid',
             'jti': 'jti-1', 'exp': mock.ANY},
            result)

    # --- 2. expired ------------------------------------------------------

    def test_expired_token_raises_expired(self):
        token = self._make_token(exp=int(time.time()) - 10)
        self.assertRaises(sf_token.Expired, sf_token.verify_sf_token, token)

    # --- 3. wrong aud ----------------------------------------------------

    def test_wrong_audience_raises_wrong_audience(self):
        token = self._make_token(aud='https://not-this-kerbside')
        self.assertRaises(
            sf_token.WrongAudience, sf_token.verify_sf_token, token)

    # --- 4. forged signature: same kid, different key ---------------------

    def test_forged_signature_same_kid_raises_bad_signature(self):
        forged_private_pem, _ = _generate_keypair()
        token = self._make_token(private_pem=forged_private_pem)
        self.assertRaises(
            sf_token.BadSignature, sf_token.verify_sf_token, token)

    # --- 5. unknown kid, refetch does not supply it ------------------------

    def test_unknown_kid_without_refetch_match_raises_unknown_kid(self):
        token = self._make_token(kid='never-cached')
        with mock.patch.object(
                sf_token, 'refresh_all_signing_keys') as mock_refresh:
            self.assertRaises(
                sf_token.UnknownKid, sf_token.verify_sf_token, token)
        mock_refresh.assert_called_once_with()

    # --- 6. unknown kid, refetch supplies it --------------------------------

    def test_unknown_kid_refetch_supplies_key_succeeds(self):
        rotated_private_pem, rotated_public_pem = _generate_keypair()
        rotated_kid = 'kid-2'
        token = self._make_token(
            private_pem=rotated_private_pem, kid=rotated_kid)

        def _fake_refresh():
            # Simulate the source having rotated: the DB now has the new
            # key cached, as refresh_all_signing_keys() would leave it.
            db.upsert_sf_token_keys(
                self.SOURCE_NAME,
                _cached_keys_json(rotated_kid, rotated_public_pem),
                time.time())

        with mock.patch.object(
                sf_token, 'refresh_all_signing_keys',
                side_effect=_fake_refresh) as mock_refresh:
            result = sf_token.verify_sf_token(token)

        mock_refresh.assert_called_once_with()
        self.assertEqual(self.SOURCE_NAME, result['source'])
        self.assertEqual('console-uuid', result['sub'])

    # --- 6b. unknown kid, refetch debounced within cooldown ----------------

    def test_unknown_kid_refetch_throttled_within_cooldown(self):
        # A refetch just happened; a second unknown-kid token within the
        # cooldown window must NOT trigger another outbound refetch. This is
        # the debounce that removes the unauthenticated amplification vector.
        token = self._make_token(kid='never-cached')
        sf_token._last_refetch_attempt = time.time()
        with mock.patch.object(
                sf_token, 'refresh_all_signing_keys') as mock_refresh:
            self.assertRaises(
                sf_token.UnknownKid, sf_token.verify_sf_token, token)
        mock_refresh.assert_not_called()

    # --- 6c. signed by a trusted key but missing a required claim ----------

    def test_missing_required_claim_raises_malformed(self):
        # Correctly signed by the trusted key but with no 'sub' claim: reject
        # cleanly as Malformed rather than KeyError-ing into a 500.
        claims = {
            'jti': 'jti-1',
            'aud': self.audience,
            'exp': int(time.time()) + 300,
        }
        token = jwt.encode(
            claims, self.private_pem, algorithm=SIGNING_ALG,
            headers={'kid': self.kid})
        self.assertRaises(
            sf_token.Malformed, sf_token.verify_sf_token, token)

    # --- 7. malformed ------------------------------------------------------

    def test_not_a_jwt_raises_malformed(self):
        self.assertRaises(
            sf_token.Malformed, sf_token.verify_sf_token, 'not-a-jwt')

    def test_non_eddsa_alg_raises_malformed(self):
        # A well-formed, correctly-signed JWT, just not EdDSA -- the
        # algorithm check must reject it before any key lookup happens.
        token = jwt.encode(
            {'sub': 'console-uuid', 'jti': 'jti-1', 'aud': self.audience,
             'exp': int(time.time()) + 300},
            'hmac-shared-secret', algorithm='HS256')
        self.assertRaises(sf_token.Malformed, sf_token.verify_sf_token, token)
