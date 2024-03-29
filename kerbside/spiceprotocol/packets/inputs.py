import struct

from kerbside.config import config

from . import constants
from . import inspection
from .scancodes import scancodes


class UnknownInputMessage(Exception):
    ...


class _SpiceInputsPacketMixin(object):
    def _decode_key_modifiers(self, buffered, message_size):
        if message_size != 2:
            self.emit_entry('Warning, unexpected key_modifiers body length!')
        modifiers = struct.unpack_from('<H', buffered, 6)[0]

        if modifiers == 0:
            self.emit_entry('   ... none')
            return

        if modifiers & constants.keyboard_modifier_flags_scroll_lock:
            self.emit_entry('   ... scroll lock')
        if modifiers & constants.keyboard_modifier_flags_num_lock:
            self.emit_entry('   ... num lock')
        if modifiers & constants.keyboard_modifier_flags_caps_lock:
            self.emit_entry('   ... caps lock')


class ClientInputsPacket(inspection.InspectableClientTraffic, _SpiceInputsPacketMixin):
    channel_identifier = 'inputs-client'

    def __call__(self, buffered):
        if len(buffered) < 6:
            return inspection.NoParsedTraffic()

        # H     UINT16 message type
        # I     UINT32 message size in bytes
        # ...          message
        message_type, message_size = struct.unpack_from('<HI', buffered)
        message_type_str = constants.client_inputs_num_to_str.get(message_type)

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

        elif message_type_str == 'key_down':
            if config.TRAFFIC_INSPECTION_INTIMATE:
                scancode = struct.unpack_from('<I', buffered, 6)[0]
                key, state = scancodes.lookup_code(scancode)
                self.emit_entry('   ... key down 0x%02x %s %s'
                                % (scancode, key, state))
            else:
                self.emit_entry('   ... key down')
            return inspection.ParsedTraffic(buffered[0: 6 + message_size],
                                            6 + message_size)

        elif message_type_str == 'key_up':
            if config.TRAFFIC_INSPECTION_INTIMATE:
                scancode = struct.unpack_from('<I', buffered, 6)[0]
                key, state = scancodes.lookup_code(scancode)
                self.emit_entry('   ... key up 0x%02x %s %s' % (scancode, key, state))
            else:
                self.emit_entry('   ... key up')
            return inspection.ParsedTraffic(buffered[0: 6 + message_size],
                                            6 + message_size)

        elif message_type_str == 'key_modifiers':
            if config.TRAFFIC_INSPECTION_INTIMATE:
                self._decode_key_modifiers(buffered, message_size)
            else:
                self.emit_entry('   ... key modifiers')
            return inspection.ParsedTraffic(buffered[0: 6 + message_size],
                                            6 + message_size)

        elif message_type_str == 'key_scancode':
            if config.TRAFFIC_INSPECTION_INTIMATE:
                for i in range(message_size):
                    scancode = struct.unpack_from('<B', buffered, 6 + i)[0]
                    key, state = scancodes.lookup_code(scancode)
                    self.emit_entry('   ... scancode 0x%02x %s %s'
                                    % (scancode, key, state))
            else:
                self.emit_entry('   ... scancodes')
            return inspection.ParsedTraffic(buffered[0: 6 + message_size],
                                            6 + message_size)

        elif message_type_str == 'mouse_motion':
            if message_size != 10:
                self.emit_entry('Warning, unexpected %s body length, expected 11!'
                                % message_type_str)
            if config.TRAFFIC_INSPECTION_INTIMATE:
                # i     INT32 x
                # i     INT32 y
                # H     UINT16 buttons state (documented as INT32, but actually INT16)
                x, y, buttons = struct.unpack_from('<iiH', buffered, 6)
                self.emit_entry('   ... delta %d,%d with buttons %d' % (x, y, buttons))
            else:
                self.emit_entry('   ... mouse motion')
            return inspection.ParsedTraffic(buffered[0: 6 + message_size],
                                            6 + message_size)

        elif message_type_str == 'mouse_position':
            if message_size != 11:
                self.emit_entry('Warning, unexpected %s body length, expected 11!'
                                % message_type_str)
            if config.TRAFFIC_INSPECTION_INTIMATE:
                # I     UINT32 x
                # I     UINT32 y
                # H     UINT16 buttons state (documented as INT32, but actually INT16)
                # B     UINT8  display id
                x, y, buttons, display_id = struct.unpack_from('<IIHB', buffered, 6)
                self.emit_entry('   ... position %d,%d with buttons %d on display %d'
                                % (x, y, buttons, display_id))
            else:
                self.emit_entry('   ... mouse position')
            return inspection.ParsedTraffic(buffered[0: 6 + message_size],
                                            6 + message_size)

        elif message_type_str == 'mouse_press':
            if message_size != 3:
                self.emit_entry('Warning, unexpected %s body length, expected 3!'
                                % message_type_str)
            if config.TRAFFIC_INSPECTION_INTIMATE:
                # H     UINT16 button state
                # B     UINT8  display id
                buttons, display_id = struct.unpack_from('<HB', buffered, 6)
                self.emit_entry('   ... button press %d on display %d'
                                % (buttons, display_id))
            else:
                self.emit_entry('   ... mouse press')
            return inspection.ParsedTraffic(buffered[0: 6 + message_size],
                                            6 + message_size)

        elif message_type_str == 'mouse_release':
            if message_size != 3:
                self.emit_entry('Warning, unexpected %s body length, expected 3!'
                                % message_type_str)
            if config.TRAFFIC_INSPECTION_INTIMATE:
                # H     UINT16 button state
                # B     UINT8  display id
                buttons, display_id = struct.unpack_from('<HB', buffered, 6)
                self.emit_entry('   ... button release %d on display %d'
                                % (buttons, display_id))
            else:
                self.emit_entry('   ... mouse release')
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


class ServerInputsPacket(inspection.InspectableServerTraffic, _SpiceInputsPacketMixin):
    channel_identifier = 'inputs-server'

    def __call__(self, buffered):
        if len(buffered) < 6:
            return inspection.NoParsedTraffic()

        # H     UINT16 message type
        # I     UINT32 message size in bytes
        # ...          message
        message_type, message_size = struct.unpack_from('<HI', buffered)
        message_type_str = constants.server_inputs_num_to_str.get(message_type)

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
                self._decode_key_modifiers(buffered, message_size)
            else:
                self.emit_entry('   ... init')
            return inspection.ParsedTraffic(buffered[0: 6 + message_size],
                                            6 + message_size)

        elif message_type_str == 'key_modifiers':
            if config.TRAFFIC_INSPECTION_INTIMATE:
                self._decode_key_modifiers(buffered, message_size)
            else:
                self.emit_entry('   ... key modifiers')
            return inspection.ParsedTraffic(buffered[0: 6 + message_size],
                                            6 + message_size)

        elif message_type_str == 'mouse_motion_ack':
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
