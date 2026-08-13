#!/usr/bin/python3

"""Dump oVirt host certificate subjects for host_subject grammar diagnostics.

Connects to the oVirt engine API the same way tools/test-ovirt-console.py
does, lists every host, and prints each host's raw
`host.certificate.subject` string -- the same value kerbside's oVirt
source scraper reads (kerbside/sources/ovirt.py:99-116) into a console's
`host_subject`. Each string is also run through a small local
re-implementation of the spice-common host-subject grammar (see
`parse_host_subject` below) and a PARSES/REJECTED verdict is printed.

This is a NON-GATING diagnostic: it always exits 0, including when the
engine is unreachable. Its only job is to put the real oVirt subject string
format into CI logs, so the question "does oVirt's format already satisfy
the spice-common grammar the Rust proxy enforces?" can be answered with
data.
"""

import argparse
import sys


def parse_args():
    parser = argparse.ArgumentParser(
        description='Dump oVirt host certificate subjects (diagnostic).'
    )
    parser.add_argument(
        '--url', required=True,
        help='oVirt Engine API URL'
    )
    parser.add_argument('--username', default='admin@internal')
    parser.add_argument('--password', required=True)
    parser.add_argument('--ca-file', required=True)
    return parser.parse_args()


def heading(text):
    print()
    print('=' * 60)
    print(text)
    print('=' * 60)


# ---------------------------------------------------------------------------
# DIAGNOSTIC APPROXIMATION of spice-common's host-subject grammar.
#
# This is a pure-Python re-implementation of the parse rules enforced by
# the Rust proxy (the `host_subject` module in ryll's
# shakenfist-spice-protocol crate, itself modelled on spice-common's
# `subject_to_x509_name` in common/ssl_verify.c). It exists ONLY to
# sanity-check the shape of the string oVirt's API returns, for CI logs.
# The Rust module is the enforcement source of truth; this function must
# never be used to gate CI or application behaviour.
#
# Grammar: comma-separated key=value entries. A backslash escapes only
# '\' and ','; anything else after a backslash is an error, including a
# trailing backslash. A space immediately before a key is skipped; all
# other whitespace is literal. An entry with no '=' (a ',' or end of
# string reached while still reading a key), or with an empty value, is
# an error. Accepted keys (case-sensitive): C, ST, L, O, OU, CN, DC,
# emailAddress.

ACCEPTED_KEYS = {'C', 'ST', 'L', 'O', 'OU', 'CN', 'DC', 'emailAddress'}


class HostSubjectParseError(Exception):
    """Raised by parse_host_subject on any grammar violation."""


def parse_host_subject(subject):
    """Parse a host-subject string per the spice-common grammar (diagnostic).

    Returns a list of (key, value) tuples in document order on success.
    Raises HostSubjectParseError with a human-readable reason otherwise.
    """
    entries = []
    key = ''
    value = ''
    in_value = False
    chars = iter(subject)

    while True:
        escaped = False
        c = next(chars, None)

        if c == '\\':
            nxt = next(chars, None)
            if nxt in ('\\', ','):
                c = nxt
                escaped = True
            else:
                raise HostSubjectParseError(
                    "invalid escape: backslash may only escape '\\' and ','")

        if not in_value:
            if c == ' ' and not key:
                continue
            elif c is None:
                if not key:
                    break
                raise HostSubjectParseError(
                    "subject ends inside entry %r (missing '=' and value)" % key)
            elif c == ',' and not escaped:
                raise HostSubjectParseError(
                    "entry %r has a ',' before any '=' (assignment is missing)" % key)
            elif c == '=' and not escaped:
                in_value = True
            else:
                key += c
        else:
            terminates = (c is None) or (c == ',' and not escaped)
            if terminates:
                if not value:
                    raise HostSubjectParseError("key %r has an empty value" % key)
                if key not in ACCEPTED_KEYS:
                    raise HostSubjectParseError(
                        "key %r is not a recognised attribute "
                        '(expected one of C, ST, L, O, OU, CN, DC, emailAddress)' % key)
                entries.append((key, value))
                if c is None:
                    break
                key = ''
                value = ''
                in_value = False
            else:
                value += c

    return entries


def print_verdict(subject):
    """Print a PARSES/REJECTED verdict line (and entries) for one subject."""
    try:
        entries = parse_host_subject(subject)
        print('    verdict: PARSES')
        for k, v in entries:
            print('      %s=%r' % (k, v))
    except HostSubjectParseError as e:
        print('    verdict: REJECTED (%s)' % e)


def self_test():
    """Sanity-check parse_host_subject against the cases in the plan."""
    assert [('C', 'US'), ('O', 'Acme'), ('CN', 'hv')] == parse_host_subject(
        'C=US,O=Acme,CN=hv')

    assert [('C', 'US'), ('O', 'Acme')] == parse_host_subject('C=US, O=Acme')

    assert [('O', 'Acme, Inc'), ('CN', 'hv')] == parse_host_subject(
        'O=Acme\\, Inc,CN=hv')

    try:
        parse_host_subject('/C=US/O=Acme')
        raise AssertionError('expected /C=US/O=Acme to be rejected')
    except HostSubjectParseError as e:
        assert "'/C'" in str(e), e

    try:
        parse_host_subject('CN=')
        raise AssertionError('expected CN= to be rejected')
    except HostSubjectParseError as e:
        assert "'CN'" in str(e), e

    print('All self-tests passed.')


def main():
    if '--self-test' in sys.argv:
        self_test()
        return

    # Imported lazily so --self-test can run (e.g. in a plain pre-commit
    # environment) without the oVirt SDK installed.
    import ovirtsdk4 as sdk

    args = parse_args()

    heading('Connect to oVirt engine')
    try:
        connection = sdk.Connection(
            url=args.url,
            username=args.username,
            password=args.password,
            ca_file=args.ca_file,
        )
        system_service = connection.system_service()
        hosts_service = system_service.hosts_service()
        hosts = hosts_service.list()
    except Exception as e:
        print('ERROR: could not reach the oVirt engine: %s' % e)
        print('This is a diagnostic-only step; continuing (exit 0).')
        sys.exit(0)

    try:
        heading('Dump host certificate subjects')
        if not hosts:
            print('  No hosts found.')

        for host in hosts:
            subject = host.certificate.subject if host.certificate else None
            print('  Host: %s' % host.name)
            print('    raw subject: %r' % subject)
            if subject is None:
                print('    verdict: SKIPPED (no certificate subject reported)')
                continue
            print_verdict(subject)

        heading('oVirt host certificate subject dump complete')
    finally:
        connection.close()

    sys.exit(0)


if __name__ == '__main__':
    main()
