import struct

from . import constants
from . import inspection


class UnknownMainMessage(Exception):
    ...


class ClientMainPacket(inspection.InspectableClientTraffic):
    channel_identifier = 'main-client'

    def __call__(self, buffered):
        if len(buffered) < 6:
            return inspection.NoParsedTraffic()

        # H     UINT16 message type
        # I     UINT32 message size in bytes
        # ...          message
        message_type, message_size = struct.unpack_from('<HI', buffered)
        message_type_str = constants.client_main_num_to_str.get(message_type)

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

        elif message_type_str == 'attach_channels':
            self.emit_entry('   ... attach channels')
            return inspection.ParsedTraffic(buffered[0: 6 + message_size],
                                            6 + message_size)

        elif not message_type_str:
            self.debug_dump(buffered)
            self.emit_entry('Client message type %d is unknown' % message_type)
            return inspection.ParsedTraffic(buffered[0: 6 + message_size],
                                            6 + message_size)

        self.debug_dump(buffered)
        self.emit_entry('Client message type %d is undecoded' % message_type)
        return inspection.ParsedTraffic(buffered[0: 6 + message_size],
                                        6 + message_size)


class ServerMainPacket(inspection.InspectableServerTraffic):
    channel_identifier = 'main-server'

    def __call__(self, buffered):
        if len(buffered) < 6:
            return inspection.NoParsedTraffic()

        # H     UINT16 message type
        # I     UINT32 message size in bytes
        # ...          message
        message_type, message_size = struct.unpack_from('<HI', buffered)
        message_type_str = constants.server_main_num_to_str.get(message_type)

        if 6 + message_size > len(buffered):
            self.emit_entry('Server %s message incomplete. Have %d, want %d'
                            % (message_type_str, len(buffered), 6 + message_size))
            return inspection.NoParsedTraffic()

        self.emit_entry('Server sent %d byte opcode %d %s'
                        % (message_size, message_type, message_type_str))
        pt = self.process_common_messages(
            buffered, message_type, message_type_str, message_size)
        if pt.length_to_consume > 0:
            return pt

        elif message_type_str == 'init':
            # I     UINT32 session id
            # I     UINT32 display channels hint
            # I     UINT32 supported mouse modes
            # I     UINT32 current mouse mode
            # I     UINT32 agent connected
            # I     UINT32 agent tokens
            # I     UINT32 multi media time
            # I     UINT32 ram hint
            (session_id, display_channels_hint, supported_mouse_modes,
             current_mouse_mode, agent_connected, agent_tokens, multi_media_time,
             ram_hint) = struct.unpack_from('<IIIIIIII', buffered, 6)
            self.emit_entry('   ... session id %d, display channels hint %d, '
                            'mouse modes %d, current mouse mode %d, agent connected %d, '
                            'agent tokens %d, multimedia time %d, ram hint %d'
                            % (session_id, display_channels_hint, supported_mouse_modes,
                                current_mouse_mode, agent_connected, agent_tokens,
                                multi_media_time, ram_hint))
            return inspection.ParsedTraffic(buffered[0: 6 + message_size],
                                            6 + message_size)

        elif message_type_str == 'channels_list':
            # I     UINT32 the number of channels
            # ... for each channel
            # ... B UINT8  type
            # ... B UINT8  id
            num_channels = struct.unpack_from('<I', buffered, 6)[0]
            self.emit_entry('   ... there are %d channels' % (num_channels))
            for i in range(num_channels):
                chan_type, chan_id = struct.unpack_from('<BB', buffered, 10 + 2 * i)
                self.emit_entry('   ... channel %d is type %s and id %d'
                                % (i, constants.channel_num_to_str[chan_type], chan_id))
            return inspection.ParsedTraffic(buffered[0: 6 + message_size],
                                            6 + message_size)

        elif not message_type_str:
            self.debug_dump(buffered)
            self.emit_entry('Server message type %d is unknown' % message_type)
            return inspection.ParsedTraffic(buffered[0: 6 + message_size],
                                            6 + message_size)

        self.debug_dump(buffered)
        self.emit_entry('Server message type %d is undecoded' % message_type)
        return inspection.ParsedTraffic(buffered[0: 6 + message_size],
                                        6 + message_size)
