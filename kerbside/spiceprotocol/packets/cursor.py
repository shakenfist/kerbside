import struct

from kerbside.config import config

from . import constants
from . import inspection


class ClientCursorPacket(inspection.InspectableClientTraffic):
    channel_identifier = 'cursor-client'

    def __call__(self, buffered):
        if len(buffered) < 6:
            return inspection.NoParsedTraffic()

        # H     UINT16 message type
        # I     UINT32 message size in bytes
        # ...          message
        message_type, message_size = struct.unpack_from('<HI', buffered)
        message_type_str = constants.client_cursor_num_to_str.get(message_type)

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

        self.debug_dump(buffered)
        self.emit_entry('Client message type %d is undecoded' % message_type)
        return inspection.ParsedTraffic(buffered[0: 6 + message_size],
                                        6 + message_size)


class ServerCursorPacket(inspection.InspectableServerTraffic):
    channel_identifier = 'cursor-server'

    def _decode_spicecursor(self, buffered, offset):
        # I     UINT32 flags
        # ... the below are a spicecursorheader...
        # Q     UINT64 unique id
        # H     UINT16 type
        # H     UINT16 width
        # H     UINT16 height
        # H     UINT16 hot spot x
        # H     UINT16 hot spot y
        flags, unique_id, cursor_type, width, height, hot_x, hot_y = \
            struct.unpack_from('<IQHHHHH', buffered, offset)
        self.emit_entry('   ... cursor flags %d, id %d, type %d, width %d, '
                        'height %d, hot spot %d,%d'
                        % (flags, unique_id, cursor_type, width, height,
                           hot_x, hot_y))

    def __call__(self, buffered):
        if len(buffered) < 6:
            return inspection.NoParsedTraffic()

        # H     UINT16 message type
        # I     UINT32 message size in bytes
        # ...          message
        message_type, message_size = struct.unpack_from('<HI', buffered)
        message_type_str = constants.server_cursor_num_to_str.get(message_type)

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
            if config.TRAFFIC_INSPECTION_INTIMATE:
                # H     UINT16 location x
                # H     UINT16 location y
                # H     UINT16 trail length
                # H     UINT16 trail frequency
                # B     UINT8  trail visibility
                # ...   current cursor shape
                x, y, tlen, tfreq, tvis = struct.unpack_from('<HHHHB', buffered, 6)
                self.emit_entry('   ... init at %d,%d with trail of %d and %d frequency, '
                                'trail %s visbile'
                                % (x, y, tlen, tfreq, {0: 'is not', 1: 'is'}[tvis]))
                if message_size > 6 + 9 + 21:
                    self._decode_spicecursor(buffered, 6 + 9)
                else:
                    self.emit_entry('   ... message too small to decode curosr')
            else:
                self.emit_entry('   ... init')
            return inspection.ParsedTraffic(buffered[0: 6 + message_size],
                                            6 + message_size)

        elif message_type_str == 'reset':
            self.emit_entry('   ... reset')
            return inspection.ParsedTraffic(buffered[0: 6 + message_size],
                                            6 + message_size)

        elif message_type_str == 'set':
            if config.TRAFFIC_INSPECTION_INTIMATE:
                # H     UINT16 location x
                # H     UINT16 location y
                # B     UINT8  visibility
                # ...   current cursor shape
                x, y, vis = struct.unpack_from('<HHB', buffered, 6)
                self.emit_entry('   ... set at %d,%d cursor %s visible'
                                % (x, y, {0: 'is not', 1: 'is'}[vis]))
            else:
                self.emit_entry('   ... set')
            return inspection.ParsedTraffic(buffered[0: 6 + message_size],
                                            6 + message_size)

        elif message_type_str == 'move':
            if config.TRAFFIC_INSPECTION_INTIMATE:
                # H     UINT16 location x
                # H     UINT16 location y
                x, y = struct.unpack_from('<HH', buffered, 6)
                self.emit_entry('   ... move to %d,%d' % (x, y))
            else:
                self.emit_entry('   ... move')
            return inspection.ParsedTraffic(buffered[0: 6 + message_size],
                                            6 + message_size)

        elif message_type_str == 'hide':
            self.emit_entry('   ... hide')
            return inspection.ParsedTraffic(buffered[0: 6 + message_size],
                                            6 + message_size)

        elif message_type_str == 'trail':
            # H     UINT16 trail length
            # H     UINT16 trail frequency
            tlen, tfreq = struct.unpack_from('<HH', buffered, 6)
            self.emit_entry('   ... trail length %d, frequency %d' % (tlen, tfreq))
            return inspection.ParsedTraffic(buffered[0: 6 + message_size],
                                            6 + message_size)

        elif message_type_str == 'invalidate_one':
            # Q     UINT cursor id
            cursor_id = struct.unpack_from('<Q', buffered, 6)[0]
            self.emit_entry('   ... invalidate cursor %d' % (cursor_id))
            return inspection.ParsedTraffic(buffered[0: 6 + message_size],
                                            6 + message_size)

        elif message_type_str == 'invalidate_all':
            self.emit_entry('   ... invalidate all cursors')
            return inspection.ParsedTraffic(buffered[0: 6 + message_size],
                                            6 + message_size)

        self.debug_dump(buffered)
        self.emit_entry('Server message type %d is undecoded' % message_type)
        return inspection.ParsedTraffic(buffered[0: 6 + message_size],
                                        6 + message_size)
