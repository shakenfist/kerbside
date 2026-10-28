#!/usr/bin/env python3

"""Show that each privilege kerbside's Proxmox VE token holds is needed.

docs/console-sources.md says the token needs VM.Audit and VM.Console, and
nothing else. A session through kerbside on that token shows the two are
enough. This shows each is needed, and that the token holds no more than
the documentation says, with three requests each of which PVE must refuse
with 403:

- the console-only token, which lacks VM.Audit, reading the smoke guest's
  configuration, which kerbside reads to discover a console and before
  every mint;
- the audit-only token, which lacks VM.Console, asking spiceproxy for the
  smoke guest's ticket, which is how kerbside mints;
- the documented token stopping the smoke guest, which needs VM.PowerMgmt.

tools/proxmox-e2e/prepare-node.sh creates the three tokens, checks that
each holds exactly the privileges named here, and lists them in its
lane-node.json.

No other request is made. A refused spiceproxy request mints nothing, so
the smoke guest's SPICE password is unchanged. If PVE wrongly accepts a
request, it has done what was asked: a ticket was minted, and the guest's
password replaced, or the guest is stopping. The lane fails either way, and
the response is never printed, because a minted ticket is a live
credential.

Usage:
    tools/proxmox-e2e/check-privileges.py --api-url URL --node NAME \\
        --vmid VMID --ca-file PATH --lane-file PATH

URL is deploy-proxmox-on-shakenfist's api_url output, NAME its node_name,
VMID its vmid and PATH its ca_file. Runs with the runner's system python3,
which has requests.
"""

import argparse
import json
import sys
import urllib.parse

import requests


# Each request is bounded, as kerbside bounds its own requests to PVE.
REQUEST_TIMEOUT = 5

# The API is never reached through an HTTP proxy, whatever the environment
# says: the runner exports a proxy which cannot route to the lane's node.
NO_PROXIES = {'http': None, 'https': None}

# (token in lane-node.json, method, path under the guest, the privilege
# whose absence or presence is shown). The power request is last, so that
# if it is wrongly accepted the other two have already been made against a
# running guest.
CHECKS = (
    ('console_only', 'GET', 'config', 'a token without VM.Audit'),
    ('audit_only', 'POST', 'spiceproxy', 'a token without VM.Console'),
    ('documented', 'POST', 'status/stop', 'the documented token, which lacks VM.PowerMgmt'),
)


def _read_secret(path):
    with open(path) as f:
        return f.read().strip()


def check(api_url, node, vmid, ca_file, tokens):
    """Make the three requests, print a line for each, and return the failures."""
    api = api_url.rstrip('/') + '/api2/json'
    failures = 0
    for name, method, action, who in CHECKS:
        token_id = tokens[name]['token_id']
        path = '/nodes/%s/qemu/%d/%s' % (node, vmid, action)
        what = '%s %s as %s (%s)' % (method, path, token_id, who)

        data = None
        if action == 'spiceproxy':
            # The same request kerbside makes to mint.
            data = {'proxy': urllib.parse.urlsplit(api_url).hostname}
        headers = {'Authorization': 'PVEAPIToken=%s=%s'
                   % (token_id, _read_secret(tokens[name]['secret_file']))}
        try:
            r = requests.request(method, api + path, headers=headers, data=data, verify=ca_file,
                                 timeout=REQUEST_TIMEOUT, proxies=NO_PROXIES, allow_redirects=False)
        except requests.exceptions.RequestException as e:
            print('FAIL: %s: the request failed: %s' % (what, e.__class__.__name__))
            failures += 1
            continue

        if r.status_code == 403:
            print('PASS: %s was refused: 403 %s' % (what, r.reason))
        else:
            # Never the body: an accepted spiceproxy request returns a ticket.
            print('FAIL: %s was not refused: %d %s' % (what, r.status_code, r.reason))
            failures += 1
    return failures


def main():
    parser = argparse.ArgumentParser(description='Show that each privilege of the Proxmox VE token is needed.')
    parser.add_argument('--api-url', required=True, help='The PVE API, https://<fqdn>:8006')
    parser.add_argument('--node', required=True, help='The PVE node name')
    parser.add_argument('--vmid', required=True, type=int, help='The smoke guest')
    parser.add_argument('--ca-file', required=True, help="The node's root CA")
    parser.add_argument('--lane-file', required=True, help="prepare-node.sh's lane-node.json")
    args = parser.parse_args()

    with open(args.lane_file) as f:
        tokens = json.load(f)['tokens']
    failures = check(args.api_url, args.node, args.vmid, args.ca_file, tokens)
    if failures:
        print('::error title=Proxmox lane::%d of %d privilege checks failed' % (failures, len(CHECKS)))
        return 1
    print('Every privilege check passed')
    return 0


if __name__ == '__main__':
    sys.exit(main())
