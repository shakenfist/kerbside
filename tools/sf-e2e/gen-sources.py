#!/usr/bin/env python3
"""Write the kerbside sources.yaml for the sf-e2e lane.

Emits exactly one ``type: shakenfist`` source pointing at the co-located
single-node Shaken Fist. The cluster CA certificate is fetched from the
running cluster (via the system client's ``get_cluster_cacert()``) and
embedded verbatim, so kerbside's source-construction CA-equality check
(``ShakenFistSource.__init__``) passes -- it compares the configured
``ca_cert`` against the freshly discovered one with only trailing
whitespace stripped. An empty CA is fine as long as it matches what the
cluster returns.

SECURITY: the source password is the SF system key, so this file is a
secret. It is written 0600 and its contents are never echoed.

Run with the kerbside venv's python (so ``shakenfist_client`` is importable).
Part of docs/plans/PLAN-kerbside-vdi-tokens-phase-09-e2e.md.
"""

import argparse
import os
import sys

import yaml

from shakenfist_client import apiclient


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        '--output', required=True,
        help='Path to write the sources.yaml to.')
    parser.add_argument(
        '--sf-url', default='http://localhost:13000',
        help='The Shaken Fist API base URL (default: %(default)s).')
    parser.add_argument(
        '--system-key', required=True,
        help='The SF system namespace key (used as the source password).')
    parser.add_argument(
        '--source-name', default='shakenfist',
        help='The kerbside source name (default: %(default)s).')
    return parser.parse_args()


def main() -> int:
    args = _parse_args()

    client = apiclient.Client(
        base_url=args.sf_url, namespace='system', key=args.system_key,
        async_strategy=apiclient.ASYNC_BLOCK)

    # Embed the cluster CA verbatim so the source's equality check matches.
    # It may legitimately be empty; that still matches an empty discovered
    # value, which is all the check requires.
    ca_cert = client.get_cluster_cacert()

    source = {
        'source': args.source_name,
        'type': 'shakenfist',
        'url': args.sf_url,
        'username': 'system',
        'password': args.system_key,
        'ca_cert': ca_cert,
    }

    # Write 0600 before the secret lands on disk.
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        yaml.safe_dump([source], f, default_flow_style=False)

    # Report only non-secret facts.
    print('[sf-e2e] wrote %s (source=%s, url=%s, ca_cert=%d bytes)'
          % (args.output, args.source_name, args.sf_url, len(ca_cert or '')),
          file=sys.stderr)
    return 0


if __name__ == '__main__':
    sys.exit(main())
