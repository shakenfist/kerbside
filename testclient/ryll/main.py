# Run a main channel

import queue
import requests
import socket
import ssl
import struct
import sys
import threading
import time

import click
from kerbside.spiceprotocol import SpiceClient
from kerbside.spiceprotocol.packets import constants

from ryll.common import _log
from ryll import display_types
from ryll import scancodes
from ryll import statistics_types


# A simple client connection is main, display, cursor, and inputs
VERBOSE = True


class _Thread:
    def __init__(self, vv, session_id, thread_type, thread_name,
                 server_message_numbers, client_message_numbers,
                 statistics_queue):
        self.vv = vv
        self.session_id = session_id
        self.thread_type = thread_type
        self.thread_name = thread_name
        self.statistics_name = thread_name.replace(' ', '_')
        self.server_message_numbers = server_message_numbers
        self.client_message_numbers = client_message_numbers
        self.statistics_queue = statistics_queue

        self.last_ping_timestamp_remote = None
        self.last_ping_timestamp_local = None

        self.buffered = bytearray()
        self.ready_to_read = True

    def _log(self, msg, severity=''):
        _log(self.thread_name, msg, severity=severity)

    def _handle_ping(self, message_size):
        # I     UINT32 id
        # Q     UINT64 timestamp
        ping_id, timestamp = struct.unpack_from('<IQ', self.buffered, 6)
        local_timestamp = time.time()

        delta_string = ''
        if self.last_ping_timestamp_remote:
            delta_remote = timestamp - self.last_ping_timestamp_remote
            delta_local = int(
                (local_timestamp - self.last_ping_timestamp_local)
                * 1000000
            )
            delta_string = (
                f' (delta of {delta_remote} remotely, '
                f'{delta_local} ns locally)'
            )

        self._log(
            f'Server ping id {ping_id}, timestamp {timestamp} {delta_string}',
            severity='debug'
        )
        self.last_ping_timestamp_remote = timestamp
        self.last_ping_timestamp_local = local_timestamp

        self._write_socket(3, 12, struct.pack('<IQ', ping_id, timestamp))
        self._log(f'Client pong id {ping_id}, timestamp {timestamp}', severity='debug')
        self.buffered = self.buffered[6 + message_size:]

    def run(self):
        self._log('Thread started')
        self.sc = SpiceClient()
        self.sc.from_vv_file(vvconfig=self.vv)
        self.sc.connect(
            connection_id=self.session_id,
            channel=constants.channel_str_to_num[self.thread_type]
        )
        self._log('Channel connected')

        self._run()

    def _read_socket(self):
        if self.ready_to_read:
            d = self.sc.sock.recv(256 * 1024)
            if not d:
                self._log('Server disconnect', severity='warn')
                sys.exit(0)

            self.ready_to_read = False
            self.buffered += d
            self.statistics_queue.put((f'{self.statistics_name}_bytes_in', len(d)))

        buffered_length = len(self.buffered)

        if buffered_length < 6:
            self.ready_to_read = True
            return None, None

        # H     UINT16 message type
        # I     UINT32 message size in bytes
        # ...          message
        message_type, message_size = struct.unpack_from('<HI', self.buffered)
        message_type_str = self.server_message_numbers.get(message_type, 'unknown')

        if 6 + message_size > buffered_length:
            self._log(
                (
                    f'Runt while awaiting {message_size} byte {message_type_str}, '
                    f'need {6 + message_size - buffered_length}'
                ),
                severity='debug'
            )
            self.ready_to_read = True
            return None, None

        self._log(
            f'Received {message_size} byte opcode {message_type} ({message_type_str})',
            severity='debug'
        )
        return message_type_str, message_size

    def _write_socket(self, message_type, message_size, message):
        if len(message) != message_size:
            self._log('Sent message does not match claimed size!')
            sys.exit(1)
        self.sc.sock.send(struct.pack('<HI', message_type, message_size) + message)
        self.statistics_queue.put((f'{self.thread_name}_bytes_out', message_size + 6))

        message_type_str = self.client_message_numbers.get(message_type, 'unknown')
        self._log(
            f'Sent {message_size} byte opcode {message_type} ({message_type_str})',
            severity='debug'
        )


class MainThread(_Thread):
    def __init__(self, vv, statistics_queue):
        super().__init__(
            vv, 0, 'main', 'main',
            constants.server_main_num_to_str,
            constants.client_main_num_to_str,
            statistics_queue)
        self.channels = []

    def _run(self):
        have_initialized = False

        while True:
            message_type_str, message_size = self._read_socket()
            if not message_type_str:
                continue

            if message_type_str == 'init':
                # I     UINT32 session id
                # I     UINT32 display channels hint
                # I     UINT32 supported mouse modes
                # I     UINT32 current mouse mode
                # I     UINT32 agent connected
                # I     UINT32 agent tokens
                # I     UINT32 multi media time
                # I     UINT32 ram hint
                (
                    self.session_id, display_channels_hint, supported_mouse_modes,
                    current_mouse_mode, agent_connected, agent_tokens,
                    multi_media_time, ram_hint
                ) = struct.unpack_from('<IIIIIIII', self.buffered, 6)
                self._log(
                    f'Server session id {self.session_id}, '
                    f'display channels hint {display_channels_hint}, '
                    f'mouse modes {supported_mouse_modes}, '
                    f'current mouse mode {current_mouse_mode}, '
                    f'agent connected {agent_connected}, '
                    f'agent tokens {agent_tokens}, '
                    f'multimedia time {multi_media_time}, '
                    f'ram hint {ram_hint}'
                )
                self.buffered = self.buffered[6 + message_size:]

                if display_channels_hint != 1:
                    self._log(
                        f'Abort: {display_channels_hint} is not a supported '
                        'number of displays'
                    )
                    sys.exit(1)

            elif message_type_str == 'channels_list':
                # I     UINT32 the number of channels
                # ... for each channel
                # ... B UINT8  type
                # ... B UINT8  id
                num_channels = struct.unpack_from('<I', self.buffered, 6)[0]
                self._log(f'There are {num_channels} channels')
                for i in range(num_channels):
                    chan_type, chan_id = struct.unpack_from(
                        '<BB', self.buffered, 10 + 2 * i)
                    chan_type_str = constants.channel_num_to_str[chan_type]
                    self._log(f'Channel {i} is type {chan_type_str} and id {chan_id}')
                    self.channels.append((chan_type_str, chan_id))
                self.buffered = self.buffered[6 + message_size:]

            elif message_type_str == 'notify':
                # Q     UINT64 timestamp
                # I     UINT32 severity
                # I     UINT32 visibility
                # I     UINT32 what
                # I     UINT32 message length
                # B[]          message
                # B     UINT8  null termination
                (
                    timestamp, severity, visibility, what, msg_len
                ) = struct.unpack_from('<QIIII', self.buffered, 6)
                msg = self.buffered[6 + 24: 6 + 24 + msg_len]
                self._log(
                    f'Message from timestamp {timestamp} with '
                    f'{constants.notify_severities_num_to_str[severity]} severity, '
                    f'{constants.notify_visibilities_num_to_str[visibility]} visibility '
                    f'{what} topic: {msg.decode("utf-8")}'
                )
                self.buffered = self.buffered[6 + message_size:]

            elif message_type_str == 'ping':
                self._handle_ping(message_size)
                if message_size > 256000 and not have_initialized:
                    self._write_socket(104, 0, b'')
                    self._log('Request channels list')
                    have_initialized = True

            else:
                self._log(
                    f'Unknown message type {message_type_str}!', severity='warn'
                )
                sys.exit(1)


class CursorThread(_Thread):
    def __init__(self, vv, session_id, statistics_queue):
        super().__init__(
            vv, session_id, 'cursor', 'cursor',
            constants.server_cursor_num_to_str,
            constants.client_cursor_num_to_str,
            statistics_queue)

    def _decode_spicecursor(self, offset):
        # I     UINT32 flags
        # ... the below are a spicecursorheader...
        # Q     UINT64 unique id
        # H     UINT16 type
        # H     UINT16 width
        # H     UINT16 height
        # H     UINT16 hot spot x
        # H     UINT16 hot spot y
        (
            flags, unique_id, cursor_type, width, height, hot_x, hot_y
        ) = struct.unpack_from('<IQHHHHH', self.buffered, offset)
        self._log(
            f'Cursor flags {flags}, id {unique_id}, type {cursor_type}, '
            f'width {width}, height {height}, hot spot {hot_x},{hot_y}'
        )

    def _run(self):
        while True:
            message_type_str, message_size = self._read_socket()
            if not message_type_str:
                continue

            if message_type_str == 'set':
                # H     UINT16 location x
                # H     UINT16 location y
                # B     UINT8  visibility
                # ...   current cursor shape
                x, y, vis = struct.unpack_from('<HHB', self.buffered, 6)
                vis_str = {0: 'is not', 1: 'is'}[vis]
                self._log(f'Pointer at {x}, {y} cursor {vis_str} visible')
                self.buffered = self.buffered[6 + message_size:]

            elif message_type_str == 'set_ack':
                # I     UINT32 generation
                # I     UINT32 window
                generation, window = struct.unpack_from(
                    '<II', self.buffered, 6)
                self._log(
                    'Server requests message acknowledgements with '
                    f'generation {generation} and window {window}'
                )
                self.buffered = self.buffered[6 + message_size:]

            elif message_type_str == 'init':
                # H     UINT16 location x
                # H     UINT16 location y
                # H     UINT16 trail length
                # H     UINT16 trail frequency
                # B     UINT8  trail visibility
                # ...   current cursor shape
                x, y, tlen, tfreq, tvis = struct.unpack_from(
                    '<HHHHB', self.buffered, 6)
                tvis_str = {0: 'is not', 1: 'is'}[tvis]
                self._log(
                    f'Initialised at {x},{y} with trail of {tlen} and '
                    f'{tfreq} frequency, trail {tvis_str} visible'
                )
                if message_size > 6 + 9 + 21:
                    self._decode_spicecursor(6 + 9)
                else:
                    self._log('Message too small to decode cursor', severity='warn')

                self.buffered = self.buffered[6 + message_size:]

            elif message_type_str == 'hide':
                self._log('Hide cursor')
                self.buffered = self.buffered[6 + message_size:]

            elif message_type_str == 'invalidate_all':
                self._log('Invalidate all cursors')
                self.buffered = self.buffered[6 + message_size:]

            elif message_type_str == 'ping':
                self._handle_ping(message_size)

            else:
                self._log(
                    f'Unknown message type {message_type_str}!', severity='warn'
                )
                sys.exit(1)


class DisplayThread(_Thread):
    def __init__(self, vv, session_id, channel_id, statistics_queue, ui_queue):
        super().__init__(
            vv, session_id, 'display', f'display {channel_id}',
            constants.server_display_num_to_str,
            constants.client_display_num_to_str,
            statistics_queue)
        self.channel_id = channel_id
        self.ui_queue = ui_queue

    def _queue_ui_command(self, command, command_args):
        self.ui_queue.put((self.channel_id, command, command_args))

    def _log(self, msg, severity=''):
        if not VERBOSE and not severity:
            return
        super()._log(msg, severity=severity)

    def _run(self):
        # B     UINT8  cache id
        # Q     UINT64 cache size
        # B     UINT8  glz dict id
        # I     UINT32 dict window size
        # These values were cargo cult'ed from remote viewer session dumps
        self._write_socket(
            101, 14, struct.pack('<BQBI', 1, 20971520, 1, 3145728))
        self._log('Initialized display session')

        ack_frequency = 0
        last_ack = 0
        message_count = 0

        while True:
            message_type_str, message_size = self._read_socket()
            if not message_type_str:
                continue

            message_count += 1

            if message_type_str == 'reset':
                self._log('Server requested display channel reset')
                self.buffered = self.buffered[6 + message_size:]

            elif message_type_str == 'set_ack':
                # I     UINT32 generation
                # I     UINT32 window
                generation, window = struct.unpack_from('<II', self.buffered, 6)
                self._log('Server requests message acknowledgements with generation '
                          f'{generation} and window {window}')
                self.buffered = self.buffered[6 + message_size:]

                # Acknowledge
                #  I     UINT32 generation
                self._write_socket(1, 4, struct.pack('<I', generation))

                ack_frequency = window
                last_ack = message_count

            elif message_type_str == 'invalidate_all_palettes':
                self._log('Server requests invalidation of all palettes')
                self.buffered = self.buffered[6 + message_size:]

            elif message_type_str == 'surface_create':
                # I     UINT32 surface id
                # I     UINT32 width
                # I     UINT32 height
                # I     UINT32 format
                # I     UINT32 flags
                surface_id, width, height, fmt, flags = struct.unpack_from(
                    '<IIIII', self.buffered, 6)
                self._log(f'Create surface id {surface_id}, size {width},{height}, '
                          f'format {fmt} with flags {flags}')
                self.buffered = self.buffered[6 + message_size:]
                self._queue_ui_command('create_window', [width, height])

            elif message_type_str == 'draw_copy':
                # SpiceMsgDisplayBase
                # I     UINT32 surface id
                # I     UINT32 rect top
                # I     UINT32 rect left
                # I     UINT32 rect bottom
                # I     UINT32 rect right
                # B     UINT8  clip type
                surface_id, top, left, bottom, right, clip_type = struct.unpack_from(
                    '<IIIIIB', self.buffered, 6)
                self._log(f'Draw copy on surface id {surface_id} in rectangle bounded '
                          f'by {left},{top} and {right},{bottom}. Clip type '
                          f'{constants.display_clip_types_num_to_str[clip_type]}.')

                offset = 27

                if constants.display_clip_types_num_to_str[clip_type] == 'rects':
                    self._log('Clip type rects is not yet decoded', severity='warn')

                # I     UINT32 address in message of source image (from end of message header)
                source_address = struct.unpack_from('<I', self.buffered, offset)[0] + 6
                self._log(f'Source image is at {source_address}')
                offset += 4

                # I     UINT32 rect top
                # I     UINT32 rect left
                # I     UINT32 rect bottom
                # I     UINT32 rect right
                stop, sleft, sbottom, sright = struct.unpack_from('<IIII', self.buffered, offset)
                self._log(f'Source rectangle is {sleft},{stop} to {sright},{sbottom}')
                offset += 16

                # H     UINT16 raster operations
                raster_ops = struct.unpack_from('<H', self.buffered, offset)[0]
                raster_ops_strs = []
                for rop in constants.rasterops:
                    if raster_ops & rop:
                        raster_ops_strs.append(constants.rasterops_num_to_str[rop])
                self._log('Raster operations %s' % '; '.join(raster_ops_strs))
                offset += 2

                # B     UNIT8  scale mode
                scale_mode = struct.unpack_from('<B', self.buffered, offset)[0]
                self._log(f'Scale mode {constants.scale_mode_num_to_str[scale_mode]}')
                offset += 1

                # B     UINT8  mask flags
                # I     UINT32 position x
                # I     UINT32 position y
                # I     UINT32 bitmap address
                mask_flags, mask_x, mask_y, mask_bitmap_address = \
                    struct.unpack_from('<BIII', self.buffered, offset)
                self._log(f'Mask flags {mask_flags} at {mask_x},{mask_y} with bitmap at '
                          f'address {mask_bitmap_address}')
                if mask_flags != 0:
                    self._log('Mask flags are not yet decoded', severity='warn')
                offset += 13

                if offset != source_address:
                    self._log('Source image is not placed directly after protocol data '
                              f'({offset} != {source_address})', severity='warn')

                # Q     UINT64 image id
                # B     UINT8  type
                # B     UINT8  flags
                # I     UINT32 width
                # I     UINT32 height
                image_id, image_type, image_flags, image_width, image_height = \
                    struct.unpack_from('<QBBII', self.buffered, offset)
                offset = source_address + 18
                self._log(f'Image id {image_id}, type {constants.image_type_num_to_str[image_type]}, '
                          f'flags {image_flags}, size {image_width}x{image_height}')

                image_type_str = constants.image_type_num_to_str[image_type]
                image_data_size = struct.unpack_from('<I', self.buffered, offset)[0]
                offset += 4

                if image_type_str == 'glz_rgb':
                    self._queue_ui_command(
                        'display_image',
                        [
                            'glz', left, top,
                            self.buffered[offset:offset + image_data_size]
                        ]
                    )
                elif image_type_str == 'lz_rgb':
                    self._queue_ui_command(
                        'display_image',
                        [
                            'lz', left, top,
                            self.buffered[offset:offset + image_data_size]
                        ]
                    )
                else:
                    self._log('Image type is undecoded', severity='warn')

                # Is there any trailing data?
                offset += image_data_size
                if message_size + 6 != offset:
                    self._log(
                        f'There are {message_size + 6 - offset} bytes of unprocessed data',
                        severity='warn')

                self.buffered = self.buffered[6 + message_size:]

            elif message_type_str == 'mark':
                # A mark is used to indicated that the new draw area is now ready to be
                # displayed. This is because there might be multiple draw commands to
                # prepare it before that first display.
                self._log('Server mark')
                self.buffered = self.buffered[6 + message_size:]
                self._queue_ui_command('mark', [time.time()])

            elif message_type_str == 'surface_destroy':
                self._log('Destroy surface')
                self.buffered = self.buffered[6 + message_size:]

            elif message_type_str == 'ping':
                self._handle_ping(message_size)

            else:
                self._log(
                    f'Unknown message type {message_type_str}!', severity='warn'
                )
                sys.exit(1)

            if ack_frequency > 0 and message_count - last_ack >= ack_frequency:
                # Send an ack
                self._write_socket(2, 0, b'')
                self._log('Client ACK')
                last_ack = message_count

            self._log(f'Client has processed {message_count - last_ack} packets since last ACK')


class InputsThread(_Thread):
    def __init__(self, vv, session_id, statistics_queue, inputs_queue, ui_queue):
        super().__init__(
            vv, session_id, 'inputs', 'inputs',
            constants.server_inputs_num_to_str,
            constants.client_inputs_num_to_str,
            statistics_queue)

        self.inputs_queue = inputs_queue
        self.ui_queue = ui_queue

    def _queue_ui_command(self, command, command_args):
        self.ui_queue.put((None, command, command_args))

    def _decode_key_modifiers(self, message_size):
        if message_size != 2:
            self.emit_entry('Warning, unexpected key_modifiers body length!')
        modifiers = struct.unpack_from('<H', self.buffered, 6)[0]

        if modifiers == 0:
            return []

        modifier_names = []
        if modifiers & constants.keyboard_modifier_flags_scroll_lock:
            modifier_names.append('scroll lock')
        if modifiers & constants.keyboard_modifier_flags_num_lock:
            modifier_names.append('num lock')
        if modifiers & constants.keyboard_modifier_flags_caps_lock:
            modifier_names.append('caps lock')

        return modifier_names

    def _run(self):
        self.sc.sock.settimeout(0)

        self._write_socket(
            103, 2,
            struct.pack('<H', constants.keyboard_modifier_flags_num_lock))
        self._log('Set key modifiers to num_lock')

        while True:
            try:
                message_type_str, message_size = self._read_socket()
                if not message_type_str:
                    continue

                if message_type_str == 'not_documented':
                    self._log('Ignoring undocumented message')
                    self.buffered = self.buffered[6 + message_size:]

                elif message_type_str in ['init', 'key_modifiers']:
                    modifier_names = self._decode_key_modifiers(message_size)
                    self._log(f'Keyboard modifiers from server: {modifier_names}')
                    self.buffered = self.buffered[6 + message_size:]

                elif message_type_str == 'mouse_motion_ack':
                    self.buffered = self.buffered[6 + message_size:]

                elif message_type_str == 'ping':
                    self._handle_ping(message_size)

                else:
                    self._log(
                        f'Unknown message type {message_type_str}!', severity='warn'
                    )
                    sys.exit(1)

            except (socket.timeout, ssl.SSLWantReadError):
                ...

            try:
                event_name, args = self.inputs_queue.get(False)
                if event_name in ['keydown', 'keyup']:
                    code, state = args
                    self._write_socket(
                        {
                            'down': 101,
                            'up': 102
                        }[state],
                        4, struct.pack('<I', code))
                    self._queue_ui_command('last_key_event', [time.time()])

                elif event_name == 'motion':
                    x, y = args
                    self._write_socket(112, 13, struct.pack('<IIIB', x, y, 0, 0))

                elif event_name == 'mouse_down':
                    button, _, _ = args
                    self._write_socket(113, 8, struct.pack('<II', button, 2 ^ button))

                elif event_name == 'mouse_up':
                    button, _, _ = args
                    self._write_socket(114, 8, struct.pack('<II', button, 2 ^ button))

            except queue.Empty:
                ...


class CadenceThread:
    def __init__(self, input_queue):
        self.input_queue = input_queue

    def run(self):
        space_down, space_up = scancodes._generate_down_and_release(57)
        while True:
            time.sleep(2)
            self.input_queue.put(('keydown', (space_down, 'down')))
            time.sleep(0.1)
            self.input_queue.put(('keyup', (space_up, 'up')))


@click.group()
@click.pass_context
def cli(ctx):
    ...


@cli.command(name='connect', help='Connect to a SPICE server')
@click.option(
    '--url', default=None, help='URL to a .vv configuration file.')
@click.option(
    '--file', type=click.Path(exists=True), default=None,
    help='Path to a .vv configuration file.')
@click.option(
    '--direct', default=None,
    help=(
        'Direct details for a SPICE console in the form '
        'HOST:INSECUREPORT[:SECUREPORT].'
    ))
@click.option(
    '--display-type', default='tkinter', help='Which display renderer to use',
    type=click.Choice(['none', 'tkinter']),
)
@click.option(
    '--statistics-type', default='tkinter', help='Which statistics renderer to use',
    type=click.Choice(['none', 'tkinter']),
)
@click.option(
    '--input-type', default='tkinter', help='Which input method to use',
    type=click.Choice(['none', 'tkinter', 'cadence']),
)
@click.pass_context
def connect(ctx, url, file, direct, display_type, statistics_type, input_type):
    # Load configuration from the various possible places
    _log('global', 'Loading config')
    vv = None
    ui_queue = queue.Queue()
    input_queue = queue.Queue()
    statistics_queue = queue.Queue()

    if url:
        vv_request = requests.get(url)
        if vv_request.status_code != 200:
            _log(
                'global',
                (
                    f'Could not fetch vv config: {vv_request.status_code}: '
                    f'{vv_request.text}'
                )
            )
            sys.exit(1)
        vv = vv_request.text
    elif file:
        with open(file) as f:
            vv = f.read()
    elif direct:
        vv = '[virt-viewer]\ntype=spice\n'

        elems = direct.split(':')
        vv += f'host={elems[0]}\n'
        vv += f'port={elems[1]}\n'
        if len(elems) > 3:
            vv += f'tls-port={elems[2]}'

    if vv:
        _log('global', 'Config loaded')
    else:
        _log('global', 'No configuration!')
        sys.exit(1)

    # Start the main channel thread
    mt_obj = MainThread(vv, statistics_queue)
    mt = threading.Thread(target=mt_obj.run, daemon=True)
    mt.start()

    # Wait for session id
    while not mt_obj.session_id:
        _log('global', 'Waiting for session id from main thread')
        time.sleep(0.5)
    _log('global', f'Have session id of {mt_obj.session_id}')

    # Attach the channels the server told us about, assuming that we support them
    channel_threads = []
    for channel_type, channel_id in mt_obj.channels:
        channel_obj = None
        if channel_type == 'cursor':
            channel_obj = CursorThread(vv, mt_obj.session_id, statistics_queue)
        elif channel_type == 'display':
            channel_obj = DisplayThread(
                vv, mt_obj.session_id, channel_id, statistics_queue, ui_queue)
        elif channel_type == 'inputs':
            channel_obj = InputsThread(
                vv, mt_obj.session_id, statistics_queue, input_queue, ui_queue)
        else:
            _log('global', f'Unsupported channel type {channel_type}, skipping')
            continue

        channel_thread = threading.Thread(target=channel_obj.run, daemon=True)
        channel_thread.start()
        channel_threads.append((channel_type, channel_id, channel_obj, channel_thread))

    # All tkinter processing needs to happen from this primary thread, so messages
    # are passed back to us on the ui_queue for processing.
    statistics_renderer = statistics_types.CHOICES[statistics_type]()
    last_statistics = time.time()

    display_renderer = display_types.CHOICES[display_type]()
    display_renderer.set_upper_window(statistics_renderer.get_upper_window())

    cadence_obj = None
    cadence_thread = None
    last_key_event = None

    latency_report = open('latency.csv', 'w')

    while True:
        try:
            while True:
                stat = statistics_queue.get(False)
                statistics_renderer.increment_statistic(*stat)

        except queue.Empty:
            ...

        try:
            ui_event = ui_queue.get(False)
            display_number, command, command_args = ui_event

            if command == 'create_window':
                width, height = command_args
                if input_type == 'tkinter':
                    iq = input_queue
                else:
                    iq = None

                if input_type == 'cadence' and not cadence_thread:
                    cadence_obj = CadenceThread(input_queue)
                    cadence_thread = threading.Thread(target=cadence_obj.run, daemon=True)
                    cadence_thread.start()

                display_renderer.create_window(display_number, width, height, iq)

            elif command == 'last_key_event':
                last_key_event = command_args[0]

            elif command == 'mark':
                ...

            elif command == 'display_image':
                if last_key_event:
                    latency = time.time() - last_key_event
                    _log('latency', f'Key event to display update: {latency}')
                    latency_report.write(f'{latency}\n')
                    latency_report.flush()
                    last_key_event = None

                if display_renderer.get_window(display_number):
                    scheme, left, top, image_data = command_args
                    display_renderer.update_window(
                        display_number, scheme, left, top, image_data)

        except queue.Empty:
            display_renderer.cascade_update()
            statistics_renderer.cascade_update()

            if time.time() - last_statistics > 10.0:
                statistics_renderer.display_statistics()
                last_statistics = time.time()

            time.sleep(0.05)
