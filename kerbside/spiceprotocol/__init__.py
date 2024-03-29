import configparser
import datetime
import os
from shakenfist_utilities import logs
import socket
import ssl
import tempfile

from .. import util

from .packets import constants
from .packets.authentication import ServerAuthPacket
from .packets.cursor import ClientCursorPacket, ServerCursorPacket      # noqa: F401
from .packets.display import ClientDisplayPacket, ServerDisplayPacket   # noqa: F401
from .packets.inputs import ClientInputsPacket, ServerInputsPacket      # noqa: F401
from .packets.linkmessages import (ClientSpiceLinkMessPacket,           # noqa: F401
                                   ServerSpiceLinkMessPacket,
                                   RetrySecured)
from .packets.main import ClientMainPacket, ServerMainPacket            # noqa: F401
from .packets.port import ClientPortPacket, ServerPortPacket            # noqa: F401
from .packets.unknown import ClientUnknownPacket, ServerUnknownPacket   # noqa: F401


LOG, _ = logs.setup(__name__, **util.configure_logging())


class ConfigureFirst(Exception):
    ...


class InvalidConfiguration(Exception):
    ...


class NoTLSPort(ConnectionError):
    ...


class HostSubjectInvalid(ConnectionError):
    ...


class CertificateInvalid(ConnectionError):
    ...


class InvalidRetry(ConnectionError):
    ...


class SpiceClient(object):
    def __init__(self):
        self.configured = False

    def from_static_configuration(self, server, port, tls_port, password, ca_cert,
                                  host_subject, secure=False):
        self.server = server
        self.port = port
        self.tls_port = tls_port
        self.secure = False
        self.password = password
        self.ca_cert = ca_cert
        self.host_subject = host_subject
        self.secure = secure

        self.configured = True

    def from_vv_file(self, vvconfig=None, vvpath=None):
        vv = configparser.ConfigParser()
        if vvpath:
            vv.read(vvpath)
        else:
            vv.read_string(vvconfig)

        if 'virt-viewer' not in vv:
            raise InvalidConfiguration(
                'There is no virt-viewer section in the configuration')

        if vv['virt-viewer'].get('type') != 'spice':
            raise InvalidConfiguration(
                'We only support virt-viewer configurations of type "spice"')

        for field in ['host', 'port']:
            if field not in vv['virt-viewer']:
                raise InvalidConfiguration(
                    'Required field "%s" missing from the virt-viewer configuration'
                    % field)

        self.server = vv['virt-viewer']['host']
        self.port = vv['virt-viewer']['port']
        self.tls_port = vv['virt-viewer'].get('tls-port')
        self.secure = False
        self.password = vv['virt-viewer'].get('password', '')
        self.ca_cert = vv['virt-viewer'].get('ca').replace('\\n', '\n')
        self.host_subject = vv['virt-viewer'].get('host-subject')

        if vv['virt-viewer']['delete-this-file'] and vvpath:
            os.unlink(vvpath)

        self.configured = True

    def connect(self,
                connection_id=0,
                channel=constants.channel_str_to_num['main'],
                common_caps=constants.default_common_caps,
                channel_caps=constants.default_channel_caps):
        if not self.configured:
            raise ConfigureFirst('You must configure the client first!')

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        if not self.secure:
            self.sock.connect((self.server, int(self.port)))
        elif self.tls_port and self.ca_cert:
            # This is another example of when we need to write the CA cert to
            # disk so we can pass it through.
            fd, ca_tempfile = tempfile.mkstemp()
            os.close(fd)
            with open(ca_tempfile, 'w') as f:
                f.write(self.ca_cert)

            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock = ssl.wrap_socket(s, ca_certs=ca_tempfile,
                                        cert_reqs=ssl.CERT_REQUIRED)
            self.sock.connect((self.server, int(self.tls_port)))

            os.unlink(ca_tempfile)
        elif self.tls_port:
            # Or we're using a system CA certificate.
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock = ssl.wrap_socket(s, cert_reqs=ssl.CERT_REQUIRED)
            self.sock.connect((self.server, int(self.tls_port)))
        else:
            raise NoTLSPort(
                'No TLS port has been configured, but a secure session was requested')

        if self.secure:
            # Validate the peer certificate
            peercert = self.sock.getpeercert()
            LOG.with_fields(peercert).debug('Peer certificate')

            host_subject = []
            host_subject_map = {
                'countryName': 'C',
                'organizationName': 'O',
                'commonName': 'CN'
            }
            for tuple in peercert['subject']:
                key = tuple[0][0]
                value = tuple[0][1]
                host_subject.append(
                    '%s=%s' % (host_subject_map.get(key, 'UNKNOWN(%s)' % key), value))

            if self.host_subject:
                if self.host_subject != ','.join(host_subject):
                    LOG.with_fields({
                        'desired': self.host_subject,
                        'received': ','.join(host_subject),
                        'received_raw': peercert['subject']
                    }).error('Host subject did not validate')
                    raise HostSubjectInvalid(
                        '%s is not %s' % (self.host_subject, ','.join(host_subject)))
                LOG.info('Host subject validated')

            now = datetime.datetime.now()
            nb = datetime.datetime.strptime(peercert.get('notBefore'),
                                            '%b %d %H:%M:%S %Y %Z')
            na = datetime.datetime.strptime(peercert.get('notAfter'),
                                            '%b %d %H:%M:%S %Y %Z')

            if now < nb:
                raise CertificateInvalid('Certificate not yet valid')
            if now > na:
                raise CertificateInvalid('Certificate has expired')
            LOG.info('Host certificate has %d days of validity remaining'
                     % (na - now).days)

        try:
            link_parser = ServerSpiceLinkMessPacket(
                LOG, self.sock, connection_id, channel, common_caps, channel_caps)
            link_parser()
            ServerAuthPacket(LOG, self.sock, link_parser.key, self.password)()

        except RetrySecured:
            if not self.secure:
                # Try again, but with a secure channel
                self.secure = True
                self.connect(connection_id, channel, common_caps, channel_caps)
                return
            raise InvalidRetry()

        except ConnectionResetError:
            raise ConnectionError('Failed to establish connection to SPICE server')
