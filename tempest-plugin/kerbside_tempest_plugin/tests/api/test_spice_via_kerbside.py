import configparser
import socket
import ssl
import struct
import tempfile
import urllib.request

from oslo_log import log as logging
from tempest.api.compute import base as compute_base
from tempest import config
from tempest.lib import decorators

CONF = config.CONF
LOG = logging.getLogger(__name__)

SPICE_MAGIC = b'REDQ'
SPICE_VERSION_MAJOR = 2
SPICE_VERSION_MINOR = 2
SPICE_CHANNEL_MAIN = 1


class SpiceViaKerbsideTestJSON(compute_base.BaseV2ComputeAdminTest):
    """Verify the SPICE console URL Nova returns is fronted by Kerbside.

    Drives Nova's get-remote-console flow with `spice-direct`/`spice`, then
    follows the returned URL to fetch the `.vv` file Kerbside serves, opens
    a TLS connection to the Kerbside SPICE proxy using the CA embedded in
    that file, and completes a minimal SPICE link handshake against the
    main channel. A SPICE magic in the reply proves the proxy is answering
    as SPICE; a fuller test that authenticates and routes through to a
    hypervisor console is a separate piece of work.
    """

    create_default_network = True

    @classmethod
    def skip_checks(cls):
        super().skip_checks()
        if not CONF.compute_feature_enabled.spice_console:
            raise cls.skipException('SPICE console feature not enabled')

    @classmethod
    def resource_setup(cls):
        super().resource_setup()
        cls.server = cls.create_test_server(wait_until='ACTIVE')

    def _fetch_vv_file(self, url):
        ctx = ssl.create_default_context(cafile=CONF.kerbside.ca_cert_path)
        request = urllib.request.Request(url)
        with urllib.request.urlopen(
                request, context=ctx,
                timeout=CONF.kerbside.handshake_timeout) as resp:
            self.assertEqual(200, resp.status,
                             'Kerbside did not return a .vv file')
            return resp.read().decode('utf-8')

    def _parse_vv_file(self, vv):
        parser = configparser.ConfigParser()
        parser.read_string(vv)
        self.assertIn('virt-viewer', parser.sections(),
                      'Kerbside .vv file is missing [virt-viewer] section')
        section = parser['virt-viewer']
        self.assertEqual('spice', section.get('type'),
                         'Kerbside .vv file is not SPICE')
        ca = section.get('ca')
        self.assertIsNotNone(
            ca, 'Kerbside .vv file did not embed a CA cert')
        return {
            'host': section['host'],
            'tls_port': int(section['tls-port']),
            'host_subject': section.get('host-subject'),
            # .vv files encode PEM newlines as literal "\n" sequences.
            'ca': ca.replace('\\n', '\n'),
        }

    def _spice_link_mess(self):
        body_size = struct.calcsize('<IBBIII')
        return struct.pack(
            '<4sIIIIBBIII',
            SPICE_MAGIC,
            SPICE_VERSION_MAJOR,
            SPICE_VERSION_MINOR,
            body_size,
            0,                       # connection_id (0 = new connection)
            SPICE_CHANNEL_MAIN,      # channel_type
            0,                       # channel_id
            0,                       # num_common_caps
            0,                       # num_channel_caps
            body_size,               # caps_offset (end of message)
        )

    def _read_link_reply_header(self, sock):
        header_fmt = '<4sIII'
        header_size = struct.calcsize(header_fmt)
        buf = b''
        while len(buf) < header_size:
            chunk = sock.recv(header_size - len(buf))
            if not chunk:
                self.fail('Kerbside closed the SPICE connection before '
                          'sending a link reply header')
            buf += chunk
        return struct.unpack(header_fmt, buf)

    @decorators.idempotent_id('a4f1b5c8-9e2d-4b3a-8c1f-6d7e8a9b0c1d')
    def test_spice_console_via_kerbside(self):
        body = self.servers_client.get_remote_console(
            self.server['id'],
            console_type='spice-direct',
            protocol='spice',
        )['remote_console']
        self.assertEqual('spice-direct', body['type'])
        self.assertEqual('spice', body['protocol'])
        url = body['url']
        LOG.info('Nova returned remote console URL: %s', url)

        vv = self._fetch_vv_file(url)
        info = self._parse_vv_file(vv)
        LOG.info(
            'Parsed Kerbside .vv: host=%s tls_port=%s host_subject=%s',
            info['host'], info['tls_port'], info['host_subject'])

        with tempfile.NamedTemporaryFile('w', suffix='.pem') as ca_file:
            ca_file.write(info['ca'])
            ca_file.flush()
            # Trust only the CA embedded in the .vv file for the SPICE
            # channel. The cert subject typically does not match the host
            # the test resolves to (it is verified out-of-band against
            # host-subject); leave that follow-up for the fuller test.
            ctx = ssl.create_default_context(cafile=ca_file.name)
            ctx.check_hostname = False

            raw = socket.create_connection(
                (info['host'], info['tls_port']),
                timeout=CONF.kerbside.handshake_timeout)
            with ctx.wrap_socket(
                    raw, server_hostname=info['host']) as sock:
                sock.sendall(self._spice_link_mess())
                magic, major, minor, _ = self._read_link_reply_header(sock)
                self.assertEqual(
                    SPICE_MAGIC, magic,
                    'Kerbside did not reply with SPICE magic; got %r'
                    % magic)
                self.assertEqual(SPICE_VERSION_MAJOR, major)
                self.assertEqual(SPICE_VERSION_MINOR, minor)
