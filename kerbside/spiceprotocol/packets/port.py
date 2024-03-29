import struct

from . import constants
from . import inspection


class ClientPortPacket(inspection.InspectableClientTraffic):
    channel_identifier = 'port-client'

    def __call__(self, buffered):
        if len(buffered) < 6:
            return inspection.NoParsedTraffic()

        # H     UINT16 message type
        # I     UINT32 message size in bytes
        # ...          message
        message_type, message_size = struct.unpack_from('<HI', buffered)
        message_type_str = constants.client_port_num_to_str.get(message_type)

        if 6 + message_size > len(buffered):
            self.emit_entry('Client %s message incomplete. Have %d, want %d'
                            % (message_type_str, len(buffered), 6 + message_size))
            return inspection.NoParsedTraffic()

        self.emit_entry('Client sent %d byte opcode %d %s'
                        % (message_size, message_type, message_type_str))
        pt = self.process_common_messages(
            buffered, message_type, message_type_str, message_size)
        if pt.length_to_consume > 0:
            return pt

        if message_type_str == 'vmc_data':
            # I     UINT32 type
            # I     UINT32 length
            # I     UINT32 id
            vmc_type, vmc_length, vmc_id = struct.unpack_from('<III', buffered, 6)
            vmc_type_str = constants.usb_redir_num_to_str.get(
                vmc_type, 'unknown (%d)' % vmc_type)
            self.emit_entry('   ... VMC type %s, length %d, id %d'
                            % (vmc_type_str, vmc_length, vmc_id))

            if vmc_type_str == 'usb_redir_hello':
                # 64s   64 character string version
                # I     UINT32 capabilities
                version, capabilities = struct.unpack_from('<64sI', buffered, 6 + 12)
                version = version.decode('utf-8').split('\x00')[0]
                self.emit_entry('   ... version: %s' % version)
                self.emit_entry('   ... capabilities: %d' % capabilities)

            else:
                self.emit_entry('   ... undecoded portion follows')
                self.debug_dump(buffered[6 + 12:6 + message_size])

            return inspection.ParsedTraffic(buffered[0: 6 + message_size],
                                            6 + message_size)

        elif message_type_str == 'vmc_compressed_data':
            self.emit_entry('vmc_compressed_data is not documented or decoded by wireshark')
            self.debug_dump(buffered[6:6 + message_size])
            return inspection.ParsedTraffic(buffered[0: 6 + message_size],
                                            6 + message_size)

        self.debug_dump(buffered)
        self.emit_entry('Client message type %d is undecoded' % message_type)
        return inspection.ParsedTraffic(buffered[0: 6 + message_size],
                                        6 + message_size)


class ServerPortPacket(ClientPortPacket):
    channel_identifier = 'port-server'
