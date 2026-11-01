#!/usr/bin/env python3

"""Write the kerbside sources.yaml for the Proxmox lane.

Emits exactly one "type: proxmox" source for the lane's PVE node, holding
the token docs/console-sources.md documents: the one
tools/proxmox-e2e/prepare-node.sh created by running that page's commands,
and listed in its lane-node.json as "documented". Kerbside is given only
this token. deploy-proxmox-on-shakenfist's own token, which holds more
than the documentation asks for, is never written here.

Three details matter and are easy to get wrong:

- The url is the action's api_url, https://<node fqdn>:8006, with nothing
  after the port. The driver appends /api2/json itself, and asks spiceproxy
  for a CONNECT proxy on the url's host, so that host is also what the
  backend leg dials on 3128. It must be the FQDN, which the action maps in
  the runner's /etc/hosts, because the node's certificate names it.
- ca_cert is inline PEM text, not a path. It is the node's root CA, the
  action's ca_file, which signs both the API's certificate and the one
  qemu's SPICE server presents through the tunnel.
- username is the token ID, user@realm!tokenid, and password its secret.
  A password login is not supported.

SECURITY: the token secret is a live credential, so this file is a secret.
It is written 0600, its contents are never printed, and it is never
uploaded. The secret is read from prepare-node.sh's 0600 file, never from
the command line.

Usage:
    tools/proxmox-e2e/gen-sources.py --output PATH --api-url URL \\
        --lane-file PATH --ca-file PATH [--source-name proxmox]
"""

# audit-allow-print: a CI command-line tool, reporting what it wrote to the step log.
import argparse
import json
import os
import sys
import urllib.parse

import yaml


class BadSource(Exception):
    pass


def proxmox_source(name, api_url, token_id, secret, ca_cert):
    """Return the sources.yaml entry for one Proxmox VE source.

    Raises BadSource, naming the problem but never the secret, for a value
    kerbside would refuse or that would leave the source unusable.
    """
    parsed = urllib.parse.urlsplit(api_url)
    if parsed.scheme != 'https' or not parsed.hostname:
        raise BadSource('the api url must be https://<node fqdn>:8006, not %s' % api_url)
    if parsed.path.rstrip('/') or parsed.query or parsed.fragment:
        raise BadSource('the api url must end at its port, as the driver appends /api2/json itself: %s' % api_url)
    if '!' not in token_id or '@' not in token_id.split('!', 1)[0]:
        raise BadSource('the token ID is not of the form user@realm!tokenid: %s' % token_id)
    if not secret or secret != secret.strip():
        raise BadSource('the secret of %s is empty or has surrounding whitespace' % token_id)
    if '-----BEGIN CERTIFICATE-----' not in ca_cert:
        raise BadSource('the CA file does not hold a PEM certificate')
    return {
        'source': name,
        'type': 'proxmox',
        'url': api_url.rstrip('/'),
        'username': token_id,
        'password': secret,
        'ca_cert': ca_cert,
    }


def write_sources(path, sources):
    """Write sources to path as YAML, 0600 before the secret lands on disk."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    # O_CREAT's mode applies only to a new file; an existing one keeps its
    # own, so it is set explicitly too.
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, 'w') as f:
        yaml.safe_dump(sources, f, default_flow_style=False)


def main():
    parser = argparse.ArgumentParser(description='Write the Proxmox lane\'s sources.yaml.')
    parser.add_argument('--output', required=True, help='Where to write sources.yaml')
    parser.add_argument('--api-url', required=True, help='The PVE API, https://<fqdn>:8006')
    parser.add_argument('--lane-file', required=True, help="prepare-node.sh's lane-node.json")
    parser.add_argument('--ca-file', required=True, help="The node's root CA")
    parser.add_argument('--source-name', default='proxmox', help='The source name (default %(default)s)')
    args = parser.parse_args()

    with open(args.lane_file) as f:
        documented = json.load(f)['tokens']['documented']
    with open(documented['secret_file']) as f:
        secret = f.read().strip()
    with open(args.ca_file) as f:
        ca_cert = f.read()

    try:
        source = proxmox_source(args.source_name, args.api_url, documented['token_id'], secret, ca_cert)
    except BadSource as e:
        print('gen-sources.py: %s' % e, file=sys.stderr)
        return 1
    write_sources(args.output, [source])

    # Only facts which are not secret.
    print('[proxmox-e2e] wrote %s (source=%s, url=%s, username=%s, ca_cert=%d bytes)'
          % (args.output, source['source'], source['url'], source['username'], len(ca_cert)),
          file=sys.stderr)
    return 0


if __name__ == '__main__':
    sys.exit(main())
