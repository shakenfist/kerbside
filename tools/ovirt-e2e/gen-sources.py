#!/usr/bin/env python3
"""Write the kerbside sources.yaml for the ovirt-e2e lane.

Emits exactly one ``type: ovirt`` source pointing at the oVirt engine built by
the lane. The engine CA certificate is fetched from the engine itself and
embedded verbatim, so kerbside's source-construction CA-equality check
(``oVirtSource.__init__``) passes -- it re-fetches the CA from the same URL,
this time *verified* against what we write here, and marks the source errored
unless the two match after ``rstrip()``.

Two details matter and are easy to get wrong:

* The ``url`` must NOT carry an ``/api`` suffix. ``_ensure_connection``
  appends ``/api`` itself, and the CA check appends
  ``/services/pki-resource?...``. The correct value looks like
  ``https://ovirt.local/ovirt-engine``.
* ``ca_cert`` is inline PEM text, not a path to a file. It is compared for
  equality against the engine's own copy, which is why we fetch it from the
  engine rather than copying ``/etc/pki/ovirt-engine/ca.pem`` around.

SECURITY: the source password is the engine admin password, so this file is a
secret. It is written 0600 and its contents are never echoed.
"""

import argparse
import os
import sys
from typing import Optional
import warnings

import requests
import urllib3
import yaml


CA_RESOURCE = '/services/pki-resource?resource=ca-certificate&format=X509-PEM-CA'


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        '--output', required=True,
        help='Path to write the sources.yaml to.')
    parser.add_argument(
        '--engine-url', required=True,
        help='The oVirt engine base URL, with no /api suffix '
             '(for example https://ovirt.local/ovirt-engine).')
    parser.add_argument(
        '--username', required=True,
        help='The engine username (for example admin@internal).')
    parser.add_argument(
        '--password', required=True,
        help='The engine password (used as the source password).')
    parser.add_argument(
        '--source-name', default='ovirt',
        help='The kerbside source name (default: %(default)s).')
    return parser.parse_args()


def _fetch_ca_cert(engine_url: str) -> Optional[str]:
    """Fetch the engine CA certificate, without verifying the engine.

    Returns the PEM text, or None (having explained itself on stderr) if the
    engine did not hand us something that looks like a certificate.

    This is the bootstrap fetch: we cannot verify the engine's HTTPS
    certificate until we hold its CA, which is the very thing we are asking
    for. ``oVirtSource.__init__`` immediately re-fetches this same URL
    *verified against the CA we write out*, and errors the source unless the
    bytes match -- so a CA that changes between the two fetches is caught.
    That is a self-consistency check, not authentication of the engine: a
    man in the middle present at bootstrap would serve a chain rooted in its
    own substituted CA and pass both. This is trust-on-first-use, acceptable
    here only because the engine sits on the lane's private test network
    with throwaway credentials; do not copy this pattern anywhere the first
    fetch crosses a network an attacker could sit on.
    """
    url = engine_url + CA_RESOURCE

    with warnings.catch_warnings():
        warnings.simplefilter(
            'ignore', urllib3.exceptions.InsecureRequestWarning)
        r = requests.get(url, verify=False, timeout=30)

    if r.status_code != 200:
        print('ERROR: fetching the engine CA from %s returned HTTP %d'
              % (url, r.status_code), file=sys.stderr)
        return None

    ca_cert = r.text
    if '-----BEGIN CERTIFICATE-----' not in ca_cert:
        print('ERROR: %s did not return a PEM certificate (%d bytes)'
              % (url, len(ca_cert)), file=sys.stderr)
        return None

    return ca_cert


def main() -> int:
    args = _parse_args()

    # No /api suffix: kerbside appends its own. Catch the common mistake here
    # rather than letting the source silently fail to connect later.
    engine_url = args.engine_url.rstrip('/')
    if engine_url.endswith('/api'):
        print('ERROR: --engine-url must not end in /api; kerbside appends it '
              '(got %s)' % args.engine_url, file=sys.stderr)
        return 1

    ca_cert = _fetch_ca_cert(engine_url)
    if ca_cert is None:
        return 1

    source = {
        'source': args.source_name,
        'type': 'ovirt',
        'url': engine_url,
        'username': args.username,
        'password': args.password,
        'ca_cert': ca_cert,
    }

    # Write 0600 before the secret lands on disk.
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        yaml.safe_dump([source], f, default_flow_style=False)

    # Report only non-secret facts.
    print('[ovirt-e2e] wrote %s (source=%s, url=%s, username=%s, '
          'ca_cert=%d bytes)'
          % (args.output, args.source_name, engine_url, args.username,
             len(ca_cert)),
          file=sys.stderr)
    return 0


if __name__ == '__main__':
    sys.exit(main())
