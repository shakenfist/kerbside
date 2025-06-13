import struct

from kerbside.spiceprotocol.packets import constants

from ryll.common import _log


class ImageDictionaryLookupFailed(Exception):
    ...


# This code is largely based on a reverse engineering of the C++ GTK GLZ decoder.
# I do not love that its duplicated between the spiceprotocol implementation in
# Kerbside and here, but it is expedient for now.
class DecompressGLZ:
    def _read_byte(self):
        d = self.image_data[self.image_offset]
        self.image_offset += 1
        return d

    def __call__(self, image_data, previous_images):
        self.image_data = image_data

        # Header. Note this is big endian, unlike most of the SPICE protocol!
        # 4s    ...    magic
        # H     UINT16 version major
        # H     UINT16 version minor
        # B     UINT8  type
        # I     UINT32 width
        # I     UINT32 height
        # I     UINT32 stride
        # Q     UINT64 image id
        # I     UINT32 image win_head_dist
        (img_magic, img_version_major, img_version_minor, img_type_packed, img_width,
         img_height, img_stride, img_id, img_win_head_dist) = \
            struct.unpack_from('>4sHHBIIIQI', image_data)
        img_magic = img_magic[::-1].decode('utf-8')
        img_type = img_type_packed & 0x0F
        img_top_down = img_type_packed >> 4
        img_type_str = constants.lz_image_type_num_to_str.get(img_type, str(img_type))
        img_ref = img_id - img_win_head_dist
        _log(
            'glz',
            (
                f'Image has magic "{img_magic}", version {img_version_major}.{img_version_minor}, '
                f'type {img_type_str}, size {img_width}x{img_height}, stride {img_stride}, '
                f'top down {img_top_down}, id {img_id}, ref {img_ref} (distance {img_win_head_dist})'
            ),
            severity='debug'
        )

        output = bytearray(img_width * img_height * 4)
        self.image_offset = 33
        out_idx = 0
        ctrl_counter = 0

        while out_idx < img_width * img_height * 4:
            ctrl = self._read_byte()
            ctrl_counter += 1

            if ctrl >= constants.lz_max_copy:
                length = ctrl >> 5
                pixel_flag = (ctrl >> 4) & 0x01
                pixel_offset = ctrl & 0x0F

                if length == 7:
                    while True:
                        code = self._read_byte()
                        length += code
                        if code != 255:
                            break

                code = self._read_byte()
                pixel_offset += code << 4

                code = self._read_byte()
                image_flag = (code >> 6) & 0x03

                if pixel_flag == 0:
                    image_dist = code & 0x3f
                    for i in range(image_flag):
                        code = self._read_byte()
                        image_dist += (code << (6 + (8 * i)))
                else:
                    pixel_flag = (code >> 5) & 0x01
                    pixel_offset += (code & 0x1f) << 12
                    image_dist = 0
                    for i in range(image_flag):
                        code = self._read_byte()
                        image_dist += (code << 8 * i)

                    if pixel_flag != 0:
                        code = self._read_byte()
                        pixel_offset += code << 17

                if image_dist == 0:
                    pixel_offset += 1

                    # pixel_offset is the number of _pixels_ to reference back
                    ref = out_idx - pixel_offset * 4
                    if pixel_offset == 1:
                        # This is a reference to the directly previous pixel
                        for i in range(length):
                            output[out_idx] = output[ref]
                            output[out_idx + 1] = output[ref + 1]
                            output[out_idx + 2] = output[ref + 2]
                            output[out_idx + 3] = output[ref + 3]
                            out_idx += 4
                    else:
                        # Otherwise, we're copying a block of previous pixels
                        for i in range(length):
                            output[out_idx] = output[ref]
                            output[out_idx + 1] = output[ref + 1]
                            output[out_idx + 2] = output[ref + 2]
                            output[out_idx + 3] = output[ref + 3]
                            out_idx += 4
                            ref += 4
                else:
                    pi_idx = pixel_offset * 4
                    for i in range(length):
                        source_id = img_id - image_dist
                        if source_id not in previous_images:
                            raise ImageDictionaryLookupFailed(
                                f'Image {source_id} not found in GLZ dictionary')

                        output[out_idx] = previous_images[source_id][pi_idx]
                        output[out_idx + 1] = previous_images[source_id][pi_idx + 1]
                        output[out_idx + 2] = previous_images[source_id][pi_idx + 2]
                        output[out_idx + 3] = previous_images[source_id][pi_idx + 3]
                        out_idx += 4
                        pi_idx += 4

            else:
                for i in range(ctrl + 1):
                    output[out_idx + 2], output[out_idx + 1], output[out_idx] = \
                        struct.unpack_from('>BBB', image_data, self.image_offset)
                    output[out_idx + 3] = 255
                    self.image_offset += 3
                    out_idx += 4

        return img_width, img_height, output, img_id


# This code is largely based on a reverse engineering of the javascript
# implementation from spice-html5. Note that this code always assumes RGB
# source data, and returns RGBA data. This matches what has been observed
# in real world use of SPICE from KVM. Again, I'm not super happy that its
# duplicated from the spiceprotocol implementation in Kerbside, but it
# was just easier right now.
class DecompressLZ(object):
    def _read_byte(self):
        d = self.image_data[self.image_offset]
        self.image_offset += 1
        return d

    def __call__(self, image_data):
        self.image_data = image_data

        # Header. Note this is big endian, unlike most of the SPICE protocol!
        # 4s    ...    magic
        # H     UINT16 version major
        # H     UINT16 version minor
        # 3s    ...    padding
        # B     UINT8  type
        # I     UINT32 width
        # I     UINT32 height
        # I     UINT32 stride
        # I     UINT32 top down
        (img_magic, img_version_major, img_version_minor, _, img_type, img_width,
         img_height, img_stride, img_top_down) = \
            struct.unpack_from('>4sHH3sBIIII', image_data)
        img_magic = img_magic[::-1].decode('utf-8')
        img_type_str = constants.lz_image_type_num_to_str.get(img_type, str(img_type))
        _log(
            'lz',
            (
                f'Image has magic "{img_magic}", version {img_version_major}.{img_version_minor}, '
                f'type {img_type_str}, size {img_width}x{img_height}, stride {img_stride}, '
                f'top down {img_top_down}'
            ),
            severity='debug'
        )

        output = bytearray(img_width * img_height * 4)
        self.image_offset = 28
        out_idx = 0
        ctrl_counter = 0

        while out_idx < img_width * img_height * 4:
            ctrl = self._read_byte()
            ctrl_counter += 1

            if ctrl >= constants.lz_max_copy:
                length = ctrl >> 5
                pixel_offset = (ctrl & 31) << 8

                if length == 7:
                    while True:
                        code = self._read_byte()
                        length += code
                        if code != 255:
                            break

                code = self._read_byte()
                pixel_offset += code

                if code == 255 and (pixel_offset - code == 31 << 8):
                    pixel_offset = struct.unpack_from('>H', image_data, self.image_offset)[0]
                    pixel_offset += 8191
                    self.image_offset += 2

                pixel_offset += 1

                # pixel_offset is the number of _pixels_ to reference back
                ref = out_idx - pixel_offset * 4
                if pixel_offset == 1:
                    # This is a reference to the directly previous pixel
                    for i in range(length):
                        output[out_idx] = output[ref]
                        output[out_idx + 1] = output[ref + 1]
                        output[out_idx + 2] = output[ref + 2]
                        output[out_idx + 3] = output[ref + 3]
                        out_idx += 4
                else:
                    # Otherwise, we're copying a block of previous pixels
                    for i in range(length):
                        output[out_idx] = output[ref]
                        output[out_idx + 1] = output[ref + 1]
                        output[out_idx + 2] = output[ref + 2]
                        output[out_idx + 3] = output[ref + 3]
                        out_idx += 4
                        ref += 4

            else:
                for i in range(ctrl + 1):
                    output[out_idx + 2], output[out_idx + 1], output[out_idx] = \
                        struct.unpack_from('>BBB', image_data, self.image_offset)
                    output[out_idx + 3] = 255
                    self.image_offset += 3
                    out_idx += 4

        return img_width, img_height, output
