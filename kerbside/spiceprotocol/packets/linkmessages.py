import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding, load_pem_public_key, PublicFormat)
import select
import struct
import time

from . import constants
from . import inspection


class ConnectionError(Exception):
    ...


class BadMagic(ConnectionError):
    ...


class BadMajor(ConnectionError):
    ...


class BadMinor(ConnectionError):
    ...


class HandshakeFailed(ConnectionError):
    ...


class RetrySecured(Exception):
    ...


def parse_capabilities(log, buffered, num_common_caps, num_channel_caps,
                       caps_offset, target, chan_type):
    log.info('Number of %s common capabilities: %d; '
             'Number of %s channel capabilities: %d; '
             'Capabilities offset: %s'
             % (target, num_common_caps, target, num_channel_caps,
                caps_offset))
    if num_common_caps > 1:
        log.warning(
            'We received more than one word of %s common capabilities '
            'but only know how to decode one word. We will ignore the rest.'
            % target)
    if num_channel_caps > 1:
        log.warning(
            'We received more than one word of %s channel capabilities '
            'but only know how to decode one word. We will ignore the rest.'
            % target)

    cur_caps_offset = 16 + caps_offset
    for _ in range(num_common_caps):
        cap = struct.unpack_from('<I', buffered, offset=cur_caps_offset)[0]
        cap_words = []
        if cap & (1 << 0):
            cap_words.append('AuthSelection')
        if cap & (1 << 1):
            cap_words.append('AuthSpice')
        if cap & (1 << 2):
            cap_words.append('AuthSASL')
        if cap & (1 << 3):
            cap_words.append('MiniHeader')
        log.info('Common %s caps: %s (%s)' % (target, cap, ', '.join(cap_words)))
        cur_caps_offset += 4

    for _ in range(num_channel_caps):
        cap = struct.unpack_from('<I', buffered, offset=cur_caps_offset)[0]
        cap_words = []
        if constants.channel_num_to_str[chan_type] == 'main':
            if cap & (1 << 0):
                cap_words.append('SemiSeamlessMigrate')
            if cap & (1 << 1):
                cap_words.append('NameAndUUID')
            if cap & (1 << 2):
                cap_words.append('AgentConnectedTokens')
            if cap & (1 << 3):
                cap_words.append('SeamlessMigrate')
        else:
            cap_words.append('--undecoded--')
        log.info('Channel %s %s caps: %s (%s)'
                 % (target, constants.channel_num_to_str[chan_type], cap,
                    ', '.join(cap_words)))
        cur_caps_offset += 4

    return cap_words


class _SpiceLinkMessPacket(object):
    magic = b'REDQ'
    major = 2
    minor = 2

    def __init__(self, log, sock):
        self.log = log
        self.sock = sock

    def _validate_protocol_magic(self, magic, major, minor):
        for field, excclass in [('magic', BadMagic), ('major', BadMajor), ('minor', BadMinor)]:
            expected = getattr(self, field)
            if locals()[field] != expected:
                raise excclass(
                    'Incorrect reply %s from %s (got %s, expected %s)'
                    % (field, self.correspondent, locals()[field], expected))


class ClientSpiceLinkMessPacket(_SpiceLinkMessPacket):
    correspondent = 'client'

    def __call__(self, buffered, redirect_to_secure=False):
        if len(buffered) < 16:
            return inspection.NoParsedTraffic()

        # ---- SpiceLinkMess ----
        # 4s    UINT32 magic value, must be equal to SPICE_MAGIC
        # I     UINT32 major_version, must be equal to SPICE_VERSION_MAJOR
        # I     UINT32 minor_version, must be equal to SPICE_VERSION_MINOR
        # I     UINT32 size number of bytes following this field to the end
        #              of this message.
        magic, major, minor, size = struct.unpack_from('<4sIII', buffered)
        self._validate_protocol_magic(magic, major, minor)

        if len(buffered) < 16 + size:
            return inspection.NoParsedTraffic()

        # I     UINT32 connection_id. In case of a new session (i.e., channel
        #              type is SPICE_CHANNEL_MAIN) this field is set to zero,
        #              and in response the server will allocate session id
        #              and will send it via the SpiceLinkReply message. In
        #              case of all other channel types, this field will be
        #              equal to the allocated session id.
        # B     UINT8  channel_type, one of SPICE_CHANNEL_?
        # B     UINT8  channel_id to connect to
        # I     UINT32 num_common_caps number of common client channel
        #              capabilities words
        # I     UINT32 num_channel_caps number of specific client channel
        #              capabilities words
        # I     UINT32 caps_offset location of the start of the capabilities
        #              vector given by the bytes offset from the “size”
        #              member (i.e., from the address of the “connection_id”
        #              member).
        # ...          capabilities
        (self.conn_id, self.chan_type, self.chan_id, self.num_common_caps,
            self.num_channel_caps, caps_offset) = \
            struct.unpack_from('<IBBIII', buffered, offset=16)
        self.log = self.log.with_fields({
            'channel_type': constants.channel_num_to_str[self.chan_type],
            'channel_id': self.chan_id,
            'connection_id': self.conn_id
        })

        # ---- SpiceLinkReply ----
        # 4s     UINT32 magic value, must be equal to SPICE_MAGIC
        # I      UINT32 major_version, must be equal to SPICE_VERSION_MAJOR
        # I      UINT32 minor_version, must be equal to SPICE_VERSION_MINOR
        # I      UINT32 size number of bytes following this field to the end
        #               of this message.
        # I      UINT32 error codes (i.e., SPICE_LINK_ERR_?)
        # B[162]        pubkey
        # I      UINT32 num_common_caps number of common client channel
        #               capabilities words
        # I      UINT32 num_channel_caps number of specific client channel
        #               capabilities words
        # I      UINT32 caps_offset location of the start of the capabilities
        #               vector given by the bytes offset from the “size”
        #               member (i.e., from the address of the “connection_id”
        #               member).

        if redirect_to_secure:
            self.sock.sendall(
                struct.pack('<4sIIII162sIII', b'REDQ', 2, 2, 162 + 16,
                            constants.error_str_to_num['need_secured'], b'',
                            0, 0, 0))
            return 16 + size

        # Store capabilities because we need them later
        parse_capabilities(
            self.log, buffered, self.num_common_caps, self.num_channel_caps,
            caps_offset, 'client', self.chan_type)
        cap_start = 16 + caps_offset
        caps_length = 4 * (self.num_common_caps + self.num_channel_caps)
        self.capabilities = buffered[cap_start: cap_start + caps_length]

        # Generate a RSA public keypair for this session
        self.private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=1024)
        self.public_key_der = self.private_key.public_key().public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

        # NOTE(mikal): I can't copy the server capabilities here because
        # we don't yet know what they are as we haven't selected a server
        # from the password yet. Therefore, they are hardcoded to what I observed
        # as common capabilities in my test environment. Specifically:
        #   common caps:  11 (AuthSelection, AuthSpice, MiniHeader)
        #   channel caps:  9 (SemiSeamlessMigrate, SeamlessMigrate)
        response = \
            struct.pack('<4sIIII162sIIIII', b'REDQ', 2, 2, 162 + 16 + 8,
                        constants.error_str_to_num['ok'], self.public_key_der,
                        1, 1, 162 + 16, 11, 9)
        self.sock.sendall(response)
        self.log.debug('Sent public key for token encryption')

        return 16 + size


class ServerSpiceLinkMessPacket(_SpiceLinkMessPacket):
    correspondent = 'server'

    def __init__(self, log, sock, connection_id, channel, common_caps, channel_caps):
        super().__init__(log, sock)
        self.connection_id = connection_id
        self.channel = channel
        self.common_caps = common_caps
        self.channel_caps = channel_caps

    def __call__(self):
        # ---- SpiceLinkMess ----
        # 4s    UINT32 magic value, must be equal to SPICE_MAGIC
        # I     UINT32 major_version, must be equal to SPICE_VERSION_MAJOR
        # I     UINT32 minor_version, must be equal to SPICE_VERSION_MINOR
        # I     UINT32 size number of bytes following this field to the end
        #              of this message.
        # I     UINT32 connection_id. In case of a new session (i.e., channel
        #              type is SPICE_CHANNEL_MAIN) this field is set to zero,
        #              and in response the server will allocate session id
        #              and will send it via the SpiceLinkReply message. In
        #              case of all other channel types, this field will be
        #              equal to the allocated session id.
        # B     UINT8  channel_type, one of SPICE_CHANNEL_?
        # B     UINT8  channel_id to connect to
        # I     UINT32 num_common_caps number of common client channel
        #              capabilities words
        # I     UINT32 num_channel_caps number of specific client channel
        #              capabilities words
        # I     UINT32 caps_offset location of the start of the capabilities
        #              vector given by the bytes offset from the “size”
        #              member (i.e., from the address of the “connection_id”
        #              member).
        # ...          capabilities
        self.sock.sendall(struct.pack(
            '<4sIIIIBBIIIII', self.magic, self.major, self.minor, 42 - 16,
            self.connection_id, self.channel, 0, 1, 1, 18, self.common_caps,
            self.channel_caps))

        # ---- SpiceLinkReply ----
        # 4s     UINT32 magic value, must be equal to SPICE_MAGIC
        # I      UINT32 major_version, must be equal to SPICE_VERSION_MAJOR
        # I      UINT32 minor_version, must be equal to SPICE_VERSION_MINOR
        # I      UINT32 size number of bytes following this field to the end
        #               of this message.
        # I      UINT32 error code
        # ...
        buffered = self.sock.recv(20)
        if not buffered:
            raise HandshakeFailed('Failed to establish connection to SPICE server')
        if len(buffered) < 20:
            raise ConnectionError('Received incomplete SpiceLinkReply header')

        magic, major, minor, size, error = struct.unpack_from('<4sIIII', buffered)
        self._validate_protocol_magic(magic, major, minor)

        if error:
            if error == constants.error_str_to_num['need_secured']:
                raise RetrySecured()

            raise ConnectionError('Received %s error from server during handshake'
                                  % constants.error_num_to_str[error])

        # Spin waiting for the whole packet
        start_time = time.time()
        while time.time() - start_time < 5:
            select.select([self.sock], [], [self.sock], 5.0)
            buffered += self.sock.recv(size - 4)
            if len(buffered) == 16 + size:
                break

        if len(buffered) < 16 + size:
            raise ConnectionError(
                'Received runt SpiceLinkReply for %s connection, expected %d '
                'got %d'
                % ({True: 'secure', False: 'insecure'}[self.secure],
                    (16 + size), len(buffered)))

        # ...
        # B[162]        pubkey used for password encryption
        # I      UINT32 num_common_caps number of common client channel
        #               capabilities words
        # I      UINT32 num_channel_caps number of specific client channel
        #               capabilities words
        # I      UINT32 caps_offset location of the start of the capabilities
        #               vector given by the bytes offset from the “size”
        #               member (i.e., from the address of the “connection_id”
        #               member).
        pubkey, num_common_caps, num_channel_caps, caps_offset = \
            struct.unpack_from('<162sIII', buffered, offset=20)
        parse_capabilities(
            self.log, buffered, num_common_caps, num_channel_caps, caps_offset,
            self.correspondent, constants.channel_str_to_num['main'])

        # Store capabilities because we need them later
        cap_start = 16 + caps_offset
        caps_length = 4 * (num_common_caps + num_channel_caps)
        self.capabilities = buffered[cap_start: cap_start + caps_length]

        # Load the public key
        base64_key = base64.b64encode(pubkey)
        pem_key = ('-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----'
                   % base64_key.decode('ascii'))
        self.key = load_pem_public_key(pem_key.encode(), default_backend())
