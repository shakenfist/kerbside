import os
import string
import struct
import time

from kerbside.config import config
from kerbside import db

from . import constants


PRINTABLE = ''
for c in string.printable:
    if c not in '\r\n\t\f\v':
        PRINTABLE += c


def update_bytes(buffered, offset, new_msg):
    idx = 0
    for b in new_msg:
        buffered[offset + idx] = b
        idx += 1


class ParsedTraffic(object):
    def __init__(self, data_to_send, length_to_consume, inserted_packets=0):
        self.data_to_send = data_to_send
        self.length_to_consume = length_to_consume
        self.inserted_packets = inserted_packets
        self.packet_is_ack = False

    def mark_as_ack(self):
        self.packet_is_ack = True


class NoParsedTraffic(ParsedTraffic):
    def __init__(self):
        super().__init__(b'', 0, 0)


class InspectableTraffic(object):
    channel_identifier = 'unknown'

    def __init__(self):
        self.logfile = None

    def configure_inspection(self, source, uuid, session_id, channel):
        if config.TRAFFIC_INSPECTION:
            self.session_dir = os.path.join(config.TRAFFIC_OUTPUT_PATH, session_id)
            os.makedirs(self.session_dir, exist_ok=True)
            self.path = os.path.join(self.session_dir, self.channel_identifier)
            self.logfile = open(self.path, 'w+')

            if config.TRAFFIC_INSPECTION_INTIMATE:
                db.add_audit_event(
                    source, uuid, session_id, channel, config.NODE_NAME, os.getpid(),
                    ('This channel is being proxied by a server configured to log '
                     'intimate details of traffic such as keystrokes and mouse '
                     'movements.'))
            else:
                db.add_audit_event(
                    source, uuid, session_id, channel, config.NODE_NAME, os.getpid(),
                    ('This channel is being proxied by a server configured to log '
                     'traffic.'))

    def emit_entry(self, entry):
        if config.TRAFFIC_INSPECTION:
            self.logfile.write('%-25s %s\n' % (time.time(), entry))
            self.logfile.flush()

    def debug_dump(self, debug_data, max_dump=100):
        # Dump some bytes to the console in a vaguely human readable format to aid
        # with debugging.
        count = 0
        b = list(debug_data)
        emit = {
            'printable': '',
            'dec': '',
            'hex': '',
        }

        while b:
            belem = b.pop(0)
            belem_utf8 = chr(belem)

            if belem_utf8 in PRINTABLE:
                emit['printable'] += belem_utf8
            else:
                emit['printable'] += '.'
            emit['dec'] += '%03d ' % belem
            emit['hex'] += '%02x ' % belem

            if len(emit['printable']) == 8:
                self.emit_entry('%-8s    %-32s    %-24s' % (emit['printable'], emit['dec'], emit['hex']))
                emit = {
                    'printable': '',
                    'dec': '',
                    'hex': '',
                }

            count += 1
            if count > max_dump:
                self.emit_entry('...truncated, %d bytes remaining...' % (len(b)))
                return

        if emit['printable']:
            self.emit_entry('%-8s    %-32s    %-24s' % (emit['printable'], emit['dec'], emit['hex']))

    def close(self):
        if self.logfile:
            self.logfile.close()


class InspectableClientTraffic(InspectableTraffic):
    def process_common_messages(self, buffered, message_type, message_type_str,
                                message_size):
        if message_size == 0:
            pt = ParsedTraffic(buffered[:6], 6)
            if message_type_str == 'ack':
                # Display channels send zero byte acks
                pt.mark_as_ack()
            return pt

        if message_type_str == 'ack_sync':
            # I     UINT32 generation
            generation = struct.unpack_from('<I', buffered, 6)[0]
            self.emit_entry('   ... client acknowledges message acknowledgements '
                            'with generation %d'
                            % generation)
            return ParsedTraffic(buffered[:6 + message_size], 6 + message_size)

        elif message_type_str == 'ack':
            # I     UINT32 generation
            generation = struct.unpack_from('<I', buffered, 6)[0]
            self.emit_entry('   ... client acknowledges message generation %d'
                            % generation)
            pt = ParsedTraffic(buffered[:6 + message_size], 6 + message_size)
            pt.mark_as_ack()
            return pt

        elif message_type_str == 'pong':
            # I     UINT32 id
            # Q     UINT64 timestamp
            ping_id, timestamp = struct.unpack_from('<IQ', buffered, 6)
            self.emit_entry('   ... id %d, timestamp %d' % (ping_id, timestamp))
            return ParsedTraffic(buffered[:6 + message_size], 6 + message_size)

        elif message_type_str == 'migrate_flush_mark':
            return ParsedTraffic(buffered[:6 + message_size], 6 + message_size)

        elif message_type_str == 'migrate_data':
            self.emit_entry('   ... migrate data')
            return ParsedTraffic(buffered[:6 + message_size], 6 + message_size)

        elif message_type_str == 'disconnecting':
            # Q     UINT64 timestamp
            # I     UINT32 reason
            timestamp, reason = struct.unpack_from('<QI', buffered, 6)
            self.emit_entry('   ... server at %d said disconnect for reason "%s"'
                            % (timestamp, constants.error_num_to_str[reason]))
            return ParsedTraffic(buffered[:6 + message_size], 6 + message_size)

        return NoParsedTraffic()


class InspectableServerTraffic(InspectableTraffic):
    def process_common_messages(self, buffered, message_type, message_type_str,
                                message_size):
        if message_size == 0:
            return ParsedTraffic(buffered[:6], 6)

        if message_type_str == 'migrate':
            migrate_flags = struct.unpack_from('<I', buffered, 6)[0]
            self.emit_entry('   ... migrate with flags %d' % migrate_flags)
            return ParsedTraffic(buffered[:6 + message_size], 6 + message_size)

        elif message_type_str == 'migrate_data':
            self.emit_entry('   ... migrate data')
            return ParsedTraffic(buffered[:6 + message_size], 6 + message_size)

        elif message_type_str == 'set_ack':
            # I     UINT32 generation
            # I     UINT32 window
            generation, window = struct.unpack_from('<II', buffered, 6)
            self.emit_entry('   ... server requests message acknowledgements '
                            'with generation %d and window %d'
                            % (generation, window))
            return ParsedTraffic(buffered[:6 + message_size], 6 + message_size)

        elif message_type_str == 'ping':
            # I     UINT32 id
            # Q     UINT64 timestamp
            ping_id, timestamp = struct.unpack_from('<IQ', buffered, 6)
            self.emit_entry('   ... id %d, timestamp %d' % (ping_id, timestamp))
            return ParsedTraffic(buffered[:6 + message_size], 6 + message_size)

        elif message_type_str == 'wait_for_channels':
            # ignored by wireshark too
            self.emit_entry('   ... server requests client wait for channel traffic')
            return ParsedTraffic(buffered[:6 + message_size], 6 + message_size)

        elif message_type_str == 'disconnecting':
            # Q     UINT64 timestamp
            # I     UINT32 reason
            timestamp, reason = struct.unpack_from('<QI', buffered, 6)
            self.emit_entry('   ... server at %d said disconnect for reason "%s"'
                            % (timestamp, constants.error_num_to_str[reason]))
            return ParsedTraffic(buffered[:6 + message_size], 6 + message_size)

        elif message_type_str == 'notify':
            # Q     UINT64 timestamp
            # I     UINT32 severity
            # I     UINT32 visibility
            # I     UINT32 what
            # I     UINT32 message length
            # B[]          message
            # B     UINT8  null termination
            timestamp, severity, visibility, what, msg_len = struct.unpack_from(
                '<QIIII', buffered, 6)
            self.emit_entry('   ... message from %d with %s severity, %s visibility '
                            'and %d topic'
                            % (timestamp, constants.notify_severities_num_to_str[severity],
                               constants.notify_visibilities_num_to_str[visibility],
                               what))
            msg = buffered[6 + 24: 6 + 24 + msg_len]
            self.emit_entry('   ... message content: %s'
                            % msg.decode('utf-8'))
            return ParsedTraffic(buffered[:6 + message_size], 6 + message_size)

        return NoParsedTraffic()
