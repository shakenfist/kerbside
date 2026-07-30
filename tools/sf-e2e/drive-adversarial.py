#!/usr/bin/env python3
"""Adversarial matrix against the live SF -> kerbside exchange.

Runs ON the SF primary with the kerbside venv's python. Exercises five
rejections against the live kerbside ``/sf-console.vv`` endpoint and the SF
mint endpoint, each asserted; any miss exits non-zero.

  (a) replay          -- a real minted token exchanged twice; the second is
                         401 "token already used".
  (b) expired         -- a token signed by a key we inject into kerbside's
                         cache, with a past ``exp`` and the correct audience;
                         401 "token expired".
  (c) wrong audience  -- same injected key, future ``exp``, ``aud`` pointing
                         elsewhere; 401 "token audience rejected".
  (d) unknown kid     -- a token signed by a throwaway key with a kid never
                         cached; 401 "unknown signing key".
  (e) cross-namespace -- a second namespace minting for the first namespace's
                         instance; SF returns 404 (ResourceNotFoundException).

Cases (b) and (c) inject a throwaway PUBLIC key (never private material) into
the shakenfist source's cached key set immediately before exchanging, to
exercise the signature-valid-but-claim-invalid paths that we cannot reach
otherwise (we do not hold the cluster's signing key). The 60s source scrape
overwrites the injected key, so each injects-then-exchanges promptly; (d)'s
unknown-kid refetch is run last because it also refreshes the cache.

SECURITY: no token string, no private key, no key material is ever printed.
Part of docs/plans/PLAN-kerbside-vdi-tokens-phase-09-e2e.md.
"""

import json
import os
import sys
import time
import uuid as uuidlib

import jwt
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from shakenfist_client import apiclient


def _load_env_file(path):
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#') or '=' not in line:
                continue
            key, value = line.split('=', 1)
            os.environ[key] = value


def _log(msg):
    print('[sf-e2e] %s' % msg, file=sys.stderr)


def _generate_keypair():
    """A fresh Ed25519 keypair as (private_pem, public_pem) strings.

    Mirrors kerbside/tests/unit/test_sf_token.py's helper: unencrypted PKCS8
    private PEM, SubjectPublicKeyInfo public PEM.
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


def _sign(private_pem, kid, sub, aud, exp):
    """Sign an EdDSA JWT shaped like an SF console token (never printed)."""
    payload = {
        'sub': sub,
        'jti': uuidlib.uuid4().hex,
        'exp': exp,
        'aud': aud,
        'iss': 'sf-e2e-adversarial',
        'iat': int(time.time()),
    }
    return jwt.encode(
        payload, private_pem, algorithm='EdDSA', headers={'kid': kid})


def _inject_cached_key(db, source, kid, public_pem):
    """Append a public key under ``kid`` to the source's cached key set.

    Preserves the real keys already cached so genuine tokens still verify.
    """
    raw = db.get_sf_token_keys(source)
    cached = json.loads(raw) if raw else {'keys': []}
    cached.setdefault('keys', []).append({
        'kid': kid,
        'alg': 'EdDSA',
        'public_pem': public_pem,
        'created': 0,
    })
    db.upsert_sf_token_keys(source, json.dumps(cached), time.time())


def _exchange(api_port, token):
    """GET the live exchange endpoint; return (status_code, body_text)."""
    url = 'http://127.0.0.1:%s/sf-console.vv' % api_port
    resp = requests.get(url, params={'token': token}, timeout=15)
    return resp.status_code, resp.text


def _inject_and_exchange(ctx, kid, private_pem, public_pem, sub, aud, exp):
    """Inject a cached key, sign, and exchange -- retrying once if the 60s
    source scrape wiped the injected key between inject and exchange (the
    tell-tale is an "unknown signing key" 401 rather than the claim error
    we are probing for).
    """
    for _ in range(2):
        _inject_cached_key(ctx['db'], ctx['source'], kid, public_pem)
        token = _sign(private_pem, kid, sub, aud, exp)
        status, body = _exchange(ctx['api_port'], token)
        if not (status == 401 and 'unknown signing key' in body.lower()):
            return status, body
    return status, body


def _expect_401(label, status, body, needle):
    if status != 401:
        raise AssertionError(
            '%s: expected HTTP 401, got %d' % (label, status))
    if needle.lower() not in body.lower():
        raise AssertionError(
            '%s: expected %r in the 401 body' % (label, needle))
    _log('%s: 401 as expected (%r)' % (label, needle))


def case_replay(ctx):
    """A real minted token exchanged twice: second is 401 already-used."""
    result = ctx['client'].get_vdi_console_proxy(ctx['instance_uuid'])
    url = result['url']
    first = requests.get(url, timeout=15)
    if first.status_code != 200:
        raise AssertionError(
            'replay: first exchange was HTTP %d, expected 200'
            % first.status_code)
    second = requests.get(url, timeout=15)
    _expect_401('replay', second.status_code, second.text, 'token already used')


def case_expired(ctx):
    """A signature-valid token with a past exp: 401 token expired."""
    private_pem, public_pem = _generate_keypair()
    kid = 'sf-e2e-expired-%s' % uuidlib.uuid4().hex[:8]
    status, body = _inject_and_exchange(
        ctx, kid, private_pem, public_pem, ctx['instance_uuid'],
        ctx['audience'], int(time.time()) - 60)
    _expect_401('expired', status, body, 'token expired')


def case_wrong_audience(ctx):
    """A signature-valid token with a foreign aud: 401 audience rejected."""
    private_pem, public_pem = _generate_keypair()
    kid = 'sf-e2e-aud-%s' % uuidlib.uuid4().hex[:8]
    status, body = _inject_and_exchange(
        ctx, kid, private_pem, public_pem, ctx['instance_uuid'],
        'https://evil.example', int(time.time()) + 300)
    _expect_401('wrong-audience', status, body, 'token audience rejected')


def case_unknown_kid(ctx):
    """A token signed by an untrusted key / unknown kid: 401 unknown key."""
    private_pem, _ = _generate_keypair()
    kid = 'sf-e2e-unknown-%s' % uuidlib.uuid4().hex[:8]
    token = _sign(
        private_pem, kid, ctx['instance_uuid'], ctx['audience'],
        int(time.time()) + 300)
    status, body = _exchange(ctx['api_port'], token)
    _expect_401('unknown-kid', status, body, 'unknown signing key')


def case_cross_namespace(ctx):
    """A second namespace minting for the first's instance: SF 404."""
    system = apiclient.Client(
        base_url=ctx['sf_url'], namespace='system',
        key=ctx['system_key'], async_strategy=apiclient.ASYNC_BLOCK)
    other_ns = 'vdie2e-other'
    other_key = uuidlib.uuid4().hex
    if other_ns in system.get_namespaces():
        system.delete_namespace(other_ns)
    system.create_namespace(other_ns)
    system.add_namespace_key(other_ns, 'e2e', other_key)
    try:
        other = apiclient.Client(
            base_url=ctx['sf_url'], namespace=other_ns, key=other_key,
            async_strategy=apiclient.ASYNC_BLOCK)
        try:
            other.get_vdi_console_proxy(ctx['instance_uuid'])
        except apiclient.ResourceNotFoundException:
            _log('cross-namespace: SF returned 404 as expected')
            return
        raise AssertionError(
            'cross-namespace: expected ResourceNotFoundException, none raised')
    finally:
        system.delete_namespace(other_ns)


def main():
    root = '/tmp/sf-e2e'
    _load_env_file(os.path.join(root, 'kerbside.env'))
    _load_env_file(os.path.join(root, 'instance.env'))

    os.environ['no_proxy'] = '127.0.0.1,localhost,' + os.environ.get(
        'no_proxy', '')

    # KERBSIDE_SQL_URL is set in the env file before this import.
    from kerbside import db

    ctx = {
        'db': db,
        'source': os.environ['KERBSIDE_SOURCE_NAME'],
        'instance_uuid': os.environ['INSTANCE_UUID'],
        'audience': os.environ['KERBSIDE_SF_CONSOLE_TOKEN_AUDIENCE'],
        'api_port': os.environ['KERBSIDE_API_PORT'],
        'sf_url': os.environ['SF_URL'],
        'namespace': os.environ['SF_NAMESPACE'],
        'namespace_key': os.environ['SF_NAMESPACE_KEY'],
        # The system key is the shakenfist source password in sources.yaml.
        'system_key': _read_source_password(
            os.environ['KERBSIDE_SOURCES_PATH']),
    }
    ctx['client'] = apiclient.Client(
        base_url=ctx['sf_url'], namespace=ctx['namespace'],
        key=ctx['namespace_key'], async_strategy=apiclient.ASYNC_BLOCK)

    # Injection-free cases first, then the injected-key cases, then the
    # unknown-kid case last (its refetch refreshes the cache).
    cases = [
        ('replay', case_replay),
        ('cross-namespace', case_cross_namespace),
        ('expired', case_expired),
        ('wrong-audience', case_wrong_audience),
        ('unknown-kid', case_unknown_kid),
    ]

    failures = []
    for label, fn in cases:
        _log('--- adversarial case: %s ---' % label)
        try:
            fn(ctx)
        except AssertionError as exc:
            _log('FAIL %s: %s' % (label, exc))
            failures.append(label)
        except Exception as exc:  # noqa: BLE001 - surface unexpected errors
            _log('ERROR %s: %s' % (label, exc))
            failures.append(label)

    if failures:
        _log('adversarial matrix FAILED: %s' % ', '.join(failures))
        return 1
    _log('adversarial matrix passed (all five cases)')
    return 0


def _read_source_password(sources_path):
    """Read the shakenfist source password (the SF system key) from yaml."""
    import yaml

    with open(sources_path) as f:
        sources = yaml.safe_load(f) or []
    for source in sources:
        if source.get('type') == 'shakenfist':
            return source['password']
    raise SystemExit('no shakenfist source in %s' % sources_path)


if __name__ == '__main__':
    sys.exit(main())
