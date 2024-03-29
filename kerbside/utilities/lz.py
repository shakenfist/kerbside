import struct

from kerbside.spiceprotocol import constants


# This code is largely based on a reverse engineering of the javascript
# implementation from spice-html5. Note that this code always assumes RGB
# source data, and returns RGBA data. This matches what has been observed
# in real world use of SPICE from KVM.
class Decompress(object):
    def _read_byte(self):
        d = self.image_data[self.image_offset]
        self.image_offset += 1
        return d

    def __call__(self, ctx, image_data):
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
        ctx.obj['LOGGER'].info('Image has magic "%s", version %d.%d, type %s, '
                               'size %dx%d, stride %d, top down %d'
                               % (img_magic, img_version_major, img_version_minor,
                                  img_type_str, img_width, img_height, img_stride,
                                  img_top_down))

        output = bytearray(img_width * img_height * 4)
        self.image_offset = 28
        out_idx = 0
        ctrl_counter = 0

        while out_idx < img_width * img_height * 4:
            ctrl = self._read_byte()

            ctx.obj['LOGGER'].debug('Control %d: %d' % (ctrl_counter, ctrl))
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
