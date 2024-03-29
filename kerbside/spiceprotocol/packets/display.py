import math
import struct

from kerbside.config import config
from . import constants
from . import inspection


class DangerZoneImages(object):
    def __init__(self):
        # Generate the "dangerzone" striped red and yellow image we use while
        # recording. This is the reference image
        r = bytearray(64 * 4)
        self.reference = bytearray(16 * 16 * 4)
        self.dangerzone_glz_base = None
        self.dangerzone_lz = None

        # Build a reference row
        offset = 0
        for _ in range(8):
            for _ in range(4):
                r[offset] = 0xFF
                r[offset + 1] = 0x66
                r[offset + 2] = 0x33
                r[offset + 3] = 0xFF
                offset += 4

            for _ in range(4):
                r[offset] = 0xFF
                r[offset + 1] = 0xCC
                r[offset + 2] = 0x33
                r[offset + 3] = 0xFF
                offset += 4

        # Every other row is the top row, shifted left by one and wrapped around
        offset = 0
        for y in range(16):
            for x in range(16):
                skew = y * 4
                self.reference[offset] = r[x * 4 + skew]
                self.reference[offset + 1] = r[x * 4 + 1 + skew]
                self.reference[offset + 2] = r[x * 4 + 2 + skew]
                self.reference[offset + 3] = r[x * 4 + 3 + skew]
                offset += 4

    def lz(self):
        if self.dangerzone_lz:
            return self.dangerzone_lz

        # The base GLZ version (doesn't refer to any other version)
        # Q     UINT64 image id -- it turns out this needs to be low or it
        #              will crash remote-viewer's cache cleanup code.
        # B     UINT8  type
        # B     UINT8  flags
        # I     UINT32 width
        # I     UINT32 height
        # I     UINT32 image data size (we update once image written)
        dangerzone_lz = struct.pack(
            '<QBBIII', 0x00, constants.image_type_str_to_num['lz_rgb'],
            0, 16, 16, 0)

        # 4s    ...    magic
        # H     UINT16 version major
        # H     UINT16 version minor
        # 3s    ...    padding
        # B     UINT8  type
        # I     UINT32 width
        # I     UINT32 height
        # I     UINT32 stride
        # I     UINT32 top down
        dangerzone_lz += struct.pack(
            '>4sHH3sBIIII', b'  ZL', 1, 1, b'', constants.lz_image_type_str_to_num['rgb32'],
            16, 16, 16 * 4, 1)

        offset = 0
        for _ in range(16):
            dangerzone_lz += struct.pack('>B', 15)
            for _ in range(16):
                dangerzone_lz += struct.pack(
                    '>BBB', self.reference[offset + 2], self.reference[offset + 1],
                    self.reference[offset])
                offset += 4

        # Update size
        self.dangerzone_lz = bytearray(dangerzone_lz)
        size = len(dangerzone_lz) - 22
        size_packed = struct.pack('<I', size)
        self.dangerzone_lz[18] = size_packed[0]
        self.dangerzone_lz[19] = size_packed[1]
        self.dangerzone_lz[20] = size_packed[2]
        self.dangerzone_lz[21] = size_packed[3]

        return self.dangerzone_lz

    def glz_base(self):
        if self.dangerzone_glz_base:
            return self.dangerzone_glz_base

        # The base GLZ version (doesn't refer to any other version)
        # Q     UINT64 image id -- it turns out this needs to be low or it
        #              will crash remote-viewer's cache cleanup code.
        # B     UINT8  type
        # B     UINT8  flags
        # I     UINT32 width
        # I     UINT32 height
        # I     UINT32 image data size (we update once image written)
        dangerzone_glz_base = struct.pack(
            '<QBBIII', 0x00, constants.image_type_str_to_num['glz_rgb'],
            0, 16, 16, 0)

        # 4s    ...    magic
        # H     UINT16 version major
        # H     UINT16 version minor
        # B     UINT8  type packed
        # I     UINT32 width
        # I     UINT32 height
        # I     UINT32 stride
        # Q     UINT64 image id
        # I     UINT32 image win_head_dist (distance from this image to its base)
        dangerzone_glz_base += struct.pack(
            '>4sHHBIIIQI', b'  ZL', 1, 1, 8, 16, 16, 4096, 0x00, 0)

        offset = 0
        for _ in range(16):
            dangerzone_glz_base += struct.pack('>B', 15)
            for _ in range(16):
                dangerzone_glz_base += struct.pack(
                    '>BBB', self.reference[offset + 2], self.reference[offset + 1],
                    self.reference[offset])
                offset += 4

        # Update size
        self.dangerzone_glz_base = bytearray(dangerzone_glz_base)
        size = len(dangerzone_glz_base) - 22
        size_packed = struct.pack('<I', size)
        self.dangerzone_glz_base[18] = size_packed[0]
        self.dangerzone_glz_base[19] = size_packed[1]
        self.dangerzone_glz_base[20] = size_packed[2]
        self.dangerzone_glz_base[21] = size_packed[3]

        return self.dangerzone_glz_base

    def glz_incremental(self, index):
        # An incremental GLZ version referring to the previous image
        # Q     UINT64 image id -- it turns out this needs to be low or it
        #              will crash remote-viewer's cache cleanup code.
        # B     UINT8  type
        # B     UINT8  flags
        # I     UINT32 width
        # I     UINT32 height
        # I     UINT32 image data size (we update once image written)
        di = struct.pack(
            '<QBBIII', index, constants.image_type_str_to_num['glz_rgb'],
            0, 16, 16, 0)

        # 4s    ...    magic
        # H     UINT16 version major
        # H     UINT16 version minor
        # B     UINT8  type packed
        # I     UINT32 width
        # I     UINT32 height
        # I     UINT32 stride
        # Q     UINT64 image id
        # I     UINT32 image win_head_dist (distance from this image to its base)
        di += struct.pack('>4sHHBIIIQI', b'  ZL', 1, 1, 8, 16, 16, 4096,  index, 1)

        for i in range(16):
            # The control byte is packed like this:
            #
            # LLLFOOOO
            #  ^ ^  ^
            #  | |  |-------------- pixel_offset = ctrl * 0x0F
            #  | |----------------- pixel_flag = (ctrl >> 4) & 0x01
            #  |------------------- length = ctrl >> 5
            #
            # If length is greater than 7, then set 7 in this packed byte, and then
            # emit N bytes of size where the bytes are single byte values and end
            # with a value less than 0xFF.
            pixel_offset = 16 * i

            # We want a length of 16 pixels, a pixel flag which doesn't cause our
            # image_dist to change from what is in the header (1 in our case),
            # and a pixel offset matching pixel_offset.
            di += struct.pack('>B', (7 << 5) + 0 + (pixel_offset & 0xF))
            di += struct.pack('>B', 16 - 7)             # Additional length
            di += struct.pack('>B', pixel_offset >> 4)  # Additional pixel offset
            di += struct.pack('>B', 1)                  # Image flag of zero, distance of 1

        # Update size
        dangerzone_incr = bytearray(di)
        size = len(dangerzone_incr) - 22
        size_packed = struct.pack('<I', size)
        dangerzone_incr[18] = size_packed[0]
        dangerzone_incr[19] = size_packed[1]
        dangerzone_incr[20] = size_packed[2]
        dangerzone_incr[21] = size_packed[3]
        return dangerzone_incr


class ClientDisplayPacket(inspection.InspectableClientTraffic):
    channel_identifier = 'display-client'

    def __call__(self, buffered):
        if len(buffered) < 6:
            return inspection.NoParsedTraffic()

        # H     UINT16 message type
        # I     UINT32 message size in bytes
        # ...          message
        message_type, message_size = struct.unpack_from('<HI', buffered)
        message_type_str = constants.client_display_num_to_str.get(message_type)

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

        elif message_type_str == 'init':
            # B     UINT8  cache id
            # Q     UINT64 cache size
            # B     UINT8  glz dict id
            # I     UINT32 dict window size
            cache_id, cache_size, glz_dict_id, dict_win_size = \
                struct.unpack_from('<BQBI', buffered, 6)
            self.emit_entry('   ... init with cache id %d, size %d, GLZ dict id '
                            '%d and window size %d'
                            % (cache_id, cache_size, glz_dict_id, dict_win_size))
            return inspection.ParsedTraffic(buffered[0: 6 + message_size],
                                            6 + message_size)

        self.debug_dump(buffered)
        self.emit_entry('Client message type %d is undecoded' % message_type)
        return inspection.ParsedTraffic(buffered[0: 6 + message_size],
                                        6 + message_size)


class ServerDisplayPacket(inspection.InspectableServerTraffic):
    channel_identifier = 'display-server'

    def __init__(self):
        super()

        self.frame_counter = 0
        if config.TRAFFIC_INSPECTION:
            self.dz = DangerZoneImages()
        else:
            self.dz = None

    def generate_border(self, width, height):
        # Top row
        for x in range(math.ceil(width / 16) + 1):
            yield (x, 0)

        # Left
        for y in range(1, math.ceil(height / 16) + 1):
            yield (0, y)

        # Right
        x = math.ceil(width / 16)
        for y in range(1, math.ceil(height / 16) + 1):
            yield (x, y)

        # Bottom
        y = math.ceil(height / 16)
        for x in range(1, math.ceil(width / 16)):
            yield (x, y)

    def __call__(self, buffered, shift_draw_copy=True):
        if len(buffered) < 6:
            return inspection.NoParsedTraffic()

        # H     UINT16 message type
        # I     UINT32 message size in bytes
        # ...          message
        message_type, message_size = struct.unpack_from('<HI', buffered)
        message_type_str = constants.server_display_num_to_str.get(message_type)

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

        elif message_type_str == 'invalidate_all_palettes':
            self.emit_entry('   ... invalidate all palettes')
            return inspection.ParsedTraffic(buffered[0: 6 + message_size],
                                            6 + message_size)

        elif message_type_str == 'surface_create':
            # I     UINT32 surface id
            # I     UINT32 width
            # I     UINT32 height
            # I     UINT32 format
            # I     UINT32 flags
            surface_id, width, height, fmt, flags = struct.unpack_from(
                '<IIIII', buffered, 6)
            self.emit_entry('   ... create surface id %d, size %d,%d, format %d '
                            'with flags %d'
                            % (surface_id, width, height, fmt, flags))

            if config.TRAFFIC_INSPECTION:
                # Tweak window size so that we can record that the session is being
                # inspected.
                inspection.update_bytes(
                    buffered, 6,
                    struct.pack('<IIIII', surface_id, width + 20, height + 20,
                                fmt, flags))
                self.emit_entry('   ... altered surface to %d by %d'
                                % (width + 20, height + 20))

                # --- Extra inserted messages ---
                extra_msgs = b''
                i = 0
                for x, y in self.generate_border(width, height):
                    # Set the background of the entire window to red in an extra message.
                    # H     UINT16 message type
                    # I     UINT32 message size in bytes
                    extra_msg = struct.pack(
                        '<HI', constants.server_display_str_to_num['draw_copy'], 0)

                    # SpiceMsgDisplayBase
                    # I     UINT32 surface id
                    # I     UINT32 rect top
                    # I     UINT32 rect left
                    # I     UINT32 rect bottom
                    # I     UINT32 rect right
                    # B     UINT8  clip type
                    extra_msg += struct.pack(
                        '<IIIIIB', surface_id, y * 16, x * 16, y * 16 + 16, x * 16 + 16,
                        constants.display_clip_types_str_to_num['rects'])

                    # Clipping rectangles
                    # I     UINT32 number of rectangles
                    # I     UINT32 rect top
                    # I     UINT32 rect left
                    # I     UINT32 rect bottom
                    # I     UINT32 rect right
                    extra_msg += struct.pack(
                        '<IIIII', 1, y * 16, x * 16, y * 16 + 16, x * 16 + 16)

                    # I     UINT32 source image offset
                    extra_msg += struct.pack('<I', 77)

                    # Source rectangle
                    # I     UINT32 rect top
                    # I     UINT32 rect left
                    # I     UINT32 rect bottom
                    # I     UINT32 rect right
                    extra_msg += struct.pack('<IIII', 0, 0, 16, 16)

                    # H     UINT16 raster operations
                    extra_msg += struct.pack('<H', constants.rasterop_put)

                    # B     UNIT8  scale mode
                    extra_msg += struct.pack(
                        '<B', constants.scale_mode_str_to_num['interpolate'])

                    # An empty mask
                    # B     UINT8  mask flags
                    # I     UINT32 position x
                    # I     UINT32 position y
                    # I     UINT32 bitmap address
                    extra_msg += struct.pack('<BIII', 0, 0, 0, 0)

                    # The image
                    # if i == 0:
                    #     extra_msg += self.dz.glz_base()
                    # else:
                    #     extra_msg += self.dz.glz_incremental(i)
                    extra_msg += self.dz.lz()

                    # Calculate message size
                    size = len(extra_msg) - 6
                    size_packed = struct.pack('<I', size)
                    extra_msg = bytearray(extra_msg)
                    extra_msg[2] = size_packed[0]
                    extra_msg[3] = size_packed[1]
                    extra_msg[4] = size_packed[2]
                    extra_msg[5] = size_packed[3]

                    extra_msgs += extra_msg
                    i += 1

            # The warning border is disabled for now because it causes OOM
            # errors on the hypervisor for reasons I do not understand -- it
            # might be because of unsolicited extra ACKs returning to the server,
            # but it is unclear to me how that would cause an OOM. I've run out
            # of time to chase this for now, and need to move onto other things.
            # This is left so I can chase again later.
            #
            # return inspection.ParsedTraffic(
            #     buffered[:6 + message_size] + extra_msgs,
            #     6 + message_size, inserted_packets=i)
            return inspection.ParsedTraffic(
                buffered[:6 + message_size], 6 + message_size)

        elif message_type_str == 'draw_copy':
            # SpiceMsgDisplayBase
            # I     UINT32 surface id
            # I     UINT32 rect top
            # I     UINT32 rect left
            # I     UINT32 rect bottom
            # I     UINT32 rect right
            # B     UINT8  clip type
            surface_id, top, left, bottom, right, clip_type = struct.unpack_from(
                '<IIIIIB', buffered, 6)
            self.emit_entry('   ... draw copy on surface id %d in rectangle bounded '
                            'by %d,%d and %d,%d. Clip type %s.'
                            % (surface_id, left, top, right, bottom,
                               constants.display_clip_types_num_to_str[clip_type]))

            # Shift window contents so that we can record the session as being
            # inspected.
            if shift_draw_copy and config.TRAFFIC_INSPECTION:
                inspection.update_bytes(
                    buffered, 6,
                    struct.pack('<IIIIIB', surface_id, top + 10, left + 10,
                                bottom + 10, right + 10, clip_type))
                self.emit_entry('   ... shifted draw copy rectangle to %d,%d and %d,%d'
                                % (left + 10, top + 10, right + 10, bottom + 10))

            offset = 27

            if constants.display_clip_types_num_to_str[clip_type] == 'rects':
                # I     UINT32 number of rectangles
                rects = struct.unpack_from('<I', buffered, offset)[0]
                offset += 4
                for i in range(rects):
                    # I     UINT32 rect top
                    # I     UINT32 rect left
                    # I     UINT32 rect bottom
                    # I     UINT32 rect right
                    rtop, rleft, rbottom, rright = struct.unpack_from(
                        '<IIII', buffered, offset)
                    self.emit_entry('   ... rect %d: %d,%d to %d,%d'
                                    % (i, rleft, rtop, rright, rbottom))
                    offset += 16

            # I     UINT32 address in message of source image (from end of message header)
            source_address = struct.unpack_from('<I', buffered, offset)[0] + 6
            self.emit_entry('   ... source image is at %d' % source_address)
            offset += 4

            # I     UINT32 rect top
            # I     UINT32 rect left
            # I     UINT32 rect bottom
            # I     UINT32 rect right
            stop, sleft, sbottom, sright = struct.unpack_from('<IIII', buffered, offset)
            self.emit_entry('   ... source rectangle is %d,%d to %d,%d'
                            % (sleft, stop, sright, sbottom))
            offset += 16

            # H     UINT16 raster operations
            raster_ops = struct.unpack_from('<H', buffered, offset)[0]
            raster_ops_strs = []
            for rop in constants.rasterops:
                if raster_ops & rop:
                    raster_ops_strs.append(constants.rasterops_num_to_str[rop])
            self.emit_entry('   ... raster operations %s' % '; '.join(raster_ops_strs))
            offset += 2

            # B     UNIT8  scale mode
            scale_mode = struct.unpack_from('<B', buffered, offset)[0]
            self.emit_entry('   ... scale mode %s'
                            % constants.scale_mode_num_to_str[scale_mode])
            offset += 1

            # B     UINT8  mask flags
            # I     UINT32 position x
            # I     UINT32 position y
            # I     UINT32 bitmap address
            mask_flags, mask_x, mask_y, mask_bitmap_address = \
                struct.unpack_from('<BIII', buffered, offset)
            self.emit_entry('   ... mask flags %d at %d,%d with bitmap at '
                            'address %d'
                            % (mask_flags, mask_x, mask_y, mask_bitmap_address))
            offset += 13

            if offset != source_address:
                self.emit_entry('   ... source image is not placed directly after '
                                'protocol data (%d != %d)'
                                % (offset, source_address))

            # Q     UINT64 image id
            # B     UINT8  type
            # B     UINT8  flags
            # I     UINT32 width
            # I     UINT32 height
            image_id, image_type, image_flags, image_width, image_height = \
                struct.unpack_from('<QBBII', buffered, offset)
            offset = source_address + 18
            self.emit_entry('   ... image id %d, type %s, flags %d, size %dx%d'
                            % (image_id, constants.image_type_num_to_str[image_type],
                               image_flags, image_width, image_height))

            if config.TRAFFIC_INSPECTION_INTIMATE:
                image_type_str = constants.image_type_num_to_str[image_type]
                if image_type_str in ['lz_rgb', 'glz_rgb']:
                    image_data_size = struct.unpack_from('<I', buffered, offset)[0]
                    offset += 4
                    image_data = buffered[offset:offset + image_data_size]

                    with open('%s-frame-%08d.%s'
                              % (self.path, self.frame_counter, image_type_str),
                              'wb') as f:
                        f.write(image_data)

                    self.emit_entry(
                        '   ... %d bytes of image data written to display-server-frame-%08d.%s'
                        % (image_data_size, self.frame_counter, image_type_str))
                    self.frame_counter += 1

                    # Is there any trailing data?
                    offset += image_data_size
                    if message_size + 6 != offset:
                        self.emit_entry('   ... There are %d bytes of unprocessed data'
                                        % (message_size + 6 - offset))
                        self.debug_dump(buffered, max_dump=(message_size + 6))

            else:
                self.emit_entry('   ... image type is undecoded')

            return inspection.ParsedTraffic(buffered[0: 6 + message_size],
                                            6 + message_size)

        self.debug_dump(buffered)
        self.emit_entry('Client message type %d is undecoded' % message_type)
        return inspection.ParsedTraffic(buffered[0: 6 + message_size],
                                        6 + message_size)
