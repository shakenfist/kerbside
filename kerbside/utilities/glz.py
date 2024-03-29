import struct

from kerbside.spiceprotocol import constants


# This code is largely based on a reverse engineering of the C++ GTK GLZ decoder.
class Decompress(object):
    def _read_byte(self):
        d = self.image_data[self.image_offset]
        self.image_offset += 1
        return d

    def __call__(self, ctx, image_data, previous_images):
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
        ctx.obj['LOGGER'].info('Image has magic "%s", version %d.%d, type %s, '
                               'size %dx%d, stride %d, top down %d, id %d, '
                               'ref %d'
                               % (img_magic, img_version_major, img_version_minor,
                                  img_type_str, img_width, img_height, img_stride,
                                  img_top_down, img_id, img_ref))

        output = bytearray(img_width * img_height * 4)
        self.image_offset = 33
        out_idx = 0
        ctrl_counter = 0

        try:
            while out_idx < img_width * img_height * 4:
                ctrl = self._read_byte()

                ctx.obj['LOGGER'].debug('Control %d: %d' % (ctrl_counter, ctrl))
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
                            output[out_idx] = previous_images[img_id - image_dist][pi_idx]
                            output[out_idx + 1] = previous_images[img_id - image_dist][pi_idx + 1]
                            output[out_idx + 2] = previous_images[img_id - image_dist][pi_idx + 2]
                            output[out_idx + 3] = previous_images[img_id - image_dist][pi_idx + 3]
                            out_idx += 4
                            pi_idx += 4

                else:
                    for i in range(ctrl + 1):
                        output[out_idx + 2], output[out_idx + 1], output[out_idx] = \
                            struct.unpack_from('>BBB', image_data, self.image_offset)
                        output[out_idx + 3] = 255
                        self.image_offset += 3
                        out_idx += 4

        except Exception as e:
            ctx.obj['LOGGER'].error('Crash while decoding: %s' % e)

        return img_width, img_height, output, img_id
