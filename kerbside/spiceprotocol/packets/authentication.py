from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import struct

from . import constants


class BadAuthentication(ConnectionError):
    ...


class AuthenticationDisconnect(ConnectionError):
    ...


class ServerAuthPacket(object):
    def __init__(self, log, sock, key, password):
        self.log = log
        self.sock = sock
        self.key = key
        self.password = password

    def __call__(self):
        # Encrypt our ticket with the public key
        encrypted_password = self.key.encrypt(
            self.password.encode() + b'\x00',
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()),
                         algorithm=hashes.SHA1(), label=None))
        if len(encrypted_password) != 128:
            raise BadAuthentication(
                'Encrypted password was %d bytes, not 128'
                % len(encrypted_password))

        # --- Client auth packet ---
        # I     UINT32 auth mechanism, should be 1
        # ...   encrypted password (128 bytes)
        self.sock.sendall(struct.pack('<I128s', 1, encrypted_password))
        self.log.info('Sent password')

        # --- Server auth response ---
        # I      UINT32 error
        d = self.sock.recv(4)
        self.log.info('Received password response')
        if not d:
            raise AuthenticationDisconnect(
                'Authentication attempt caused server disconnect')

        error = struct.unpack_from('<I', d)[0]
        if error:
            raise BadAuthentication(
                'Received %s error from server during authentication'
                % constants.error_num_to_str[error])
