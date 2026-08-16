import os
import re
import uuid

import testtools


def _repo_file(*parts):
    """Return the contents of a repository file, or None outside a checkout.

    The demo stack is repository data, not package data: nothing under
    demo/ is beneath a package directory, so setuptools_scm's file
    finder does not contribute it and no wheel contains it. The tests
    walk up from __file__ for the same reason test_conf_example.py
    does.
    """
    path = os.path.dirname(os.path.abspath(__file__))
    while path != '/':
        candidate = os.path.join(path, *parts)
        if os.path.isfile(candidate):
            with open(candidate) as f:
                return f.read()
        path = os.path.dirname(path)
    return None


def _require(*parts):
    text = _repo_file(*parts)
    if text is None:
        raise testtools.TestCase.skipException(
            'no %s above %s; not running from a checkout, and the demo '
            'stack does not ship in the wheel'
            % (os.path.join(*parts), os.path.abspath(__file__)))
    return text


class DemoStackCouplingTestCase(testtools.TestCase):
    """Values the demo repeats in two files, pinned in one place.

    The demo works only because several strings agree across files
    that are edited for unrelated reasons. Each of them is currently
    protected by a comment asking the next person to remember, which
    is the weakest kind of protection: nothing fails until someone
    starts the stack and reads a TLS or authentication error that does
    not name the cause.

    None of these can be derived from the code, so the tests compare
    the files to each other rather than to a constant written here --
    a constant would just be a third copy to keep in step.
    """

    def test_the_host_subject_matches_the_certificate_it_describes(self):
        """PROXY_HOST_SUBJECT is what the *client* checks.

        generate-tls.sh issues the proxy certificate with a fixed
        subject, and docker-compose.yml tells kerbside to advertise
        that same string in every .vv. If they drift, the certificate
        still verifies against the CA and remote-viewer still refuses
        the session, because the subject it was told to expect is not
        the one presented.
        """
        tls = _require('tools', 'direct-qemu', 'generate-tls.sh')
        compose = _require('demo', 'docker-compose.yml')

        match = re.search(
            r"-subj\s+'(/C=[^']*/CN=kerbside-ci)'", tls)
        self.assertIsNotNone(
            match,
            'generate-tls.sh no longer has a recognisable -subj for the '
            'proxy certificate; the demo pins that subject and this test '
            'can no longer tell whether they agree')

        # openssl writes /A=1/B=2, kerbside and SPICE write A=1,B=2.
        expected = match.group(1).lstrip('/').replace('/', ',')

        match = re.search(
            r'KERBSIDE_PROXY_HOST_SUBJECT:\s*\'([^\']*)\'', compose)
        self.assertIsNotNone(
            match, 'demo/docker-compose.yml no longer sets '
                   'KERBSIDE_PROXY_HOST_SUBJECT')

        self.assertEqual(
            expected, match.group(1),
            'demo/docker-compose.yml advertises a host subject that is '
            'not the one tools/direct-qemu/generate-tls.sh puts in the '
            'proxy certificate, so remote-viewer will refuse the demo '
            'session')

    def test_the_spice_ticket_matches_the_server_that_demands_it(self):
        """The ticket is a shared secret between two files.

        spice-target's qemu is started with a ticket, and
        demo/sources.yaml is what kerbside presents to the backend. A
        mismatch fails at connect time with a SPICE authentication
        error, well away from either file.
        """
        target = _require('demo', 'spice-target', 'Dockerfile')
        sources = _require('demo', 'sources.yaml')

        match = re.search(r'secret,id=spice-ticket,data=([\w-]+)', target)
        self.assertIsNotNone(
            match,
            'demo/spice-target/Dockerfile no longer passes the ticket as '
            '-object secret. Note that the inline "password=" form is not '
            'an alternative: it was removed in newer qemu and fails on '
            'qemu 10 (see tools/direct-qemu/start-qemu.sh)')

        self.assertIn(
            'ticket: "%s"' % match.group(1), sources,
            'demo/sources.yaml does not carry the ticket that '
            'demo/spice-target/Dockerfile starts qemu with, so kerbside '
            'will fail to authenticate to the SPICE server')

    def test_the_demo_console_uuid_is_a_uuid(self):
        """The static driver will not catch this; something later will.

        StaticSource treats uuid as an opaque string, so an invalid one
        works right up until anything downstream parses it properly --
        and the demo is the worst place to discover that.
        """
        sources = _require('demo', 'sources.yaml')

        match = re.search(r'^\s*- uuid:\s*"([^"]+)"', sources, re.M)
        self.assertIsNotNone(match, 'demo/sources.yaml has no console uuid')

        try:
            uuid.UUID(match.group(1))
        except ValueError:
            self.fail('demo/sources.yaml console uuid %r is not a valid '
                      'UUID' % match.group(1))
