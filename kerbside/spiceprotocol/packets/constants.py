import copy


# Map channel types back and forth
channel_str_to_num = {
    'main': 1,
    'display': 2,
    'inputs': 3,
    'cursor': 4,
    'playback': 5,
    'record': 6,
    'tunnel (obsolete)': 7,
    'usbredir': 8,
    'port': 9,
    'webdav': 10
}


channel_num_to_str = {
    1: 'main',
    2: 'display',
    3: 'inputs',
    4: 'cursor',
    5: 'playback',
    6: 'record',
    7: 'tunnel (obsolete)',
    8: 'usbredir',
    9: 'port',
    10: 'webdav'
}


# Map error numbers back and forth
error_str_to_num = {
    'ok': 0,
    'error': 1,
    'invalid_magic': 2,
    'invalid_data': 3,
    'version_mismatch': 4,
    'need_secured': 5,
    'need_unsecured': 6,
    'permission_denied': 7,
    'bad_connection_id': 8,
    'channel_unavailable': 9
}


error_num_to_str = {
    0: 'ok',
    1: 'error',
    2: 'invalid_magic',
    3: 'invalid_data',
    4: 'version_mismatch',
    5: 'need_secured',
    6: 'need_unsecured',
    7: 'permission_denied',
    8: 'bad_connection_id',
    9: 'channel_unavailable'
}

# These are hardcoded to what I observed as common capabilities in my test
# environment.
default_common_caps = 11  # AuthSelection, AuthSpice, MiniHeader
default_channel_caps = 9  # SemiSeamlessMigrate, SeamlessMigrate

# Notify message severities
notify_severities_num_to_str = {
    0: 'info',
    1: 'warn',
    2: 'error'
}

notify_visibilities_num_to_str = {
    0: 'low',
    1: 'medium',
    2: 'high'
}

# Common message types client to server
client_common_num_to_str = {
    1: 'ack_sync',
    2: 'ack',
    3: 'pong',
    4: 'migrate_flush_mark',
    5: 'migrate_data',
    6: 'disconnecting',
}

# Main message types from client to server
client_main_num_to_str = copy.copy(client_common_num_to_str)
client_main_num_to_str.update({
    104: 'attach_channels'
})

# Display message types from client to server
client_display_num_to_str = copy.copy(client_common_num_to_str)
client_display_num_to_str.update({
    101: 'init'
})

# Input message types client to server
client_inputs_num_to_str = copy.copy(client_common_num_to_str)
client_inputs_num_to_str.update({
    101: 'key_down',
    102: 'key_up',
    103: 'key_modifiers',
    104: 'key_scancode',
    111: 'mouse_motion',
    112: 'mouse_position',
    113: 'mouse_press',
    114: 'mouse_release'
})

# Cursor message types from client to server
client_cursor_num_to_str = copy.copy(client_common_num_to_str)

# Port (USB redirection) message types client to server
client_port_num_to_str = copy.copy(client_common_num_to_str)
client_port_num_to_str.update({
    101: 'vmc_data',
    102: 'vmc_compressed_data'
})

# Common message types server to client
server_common_num_to_str = {
    1: 'migrate',
    2: 'migrate_data',
    3: 'set_ack',
    4: 'ping',
    5: 'wait_for_channels',
    6: 'disconnecting',
    7: 'notify'
}

server_common_str_to_num = {
    'migrate': 1,
    'migrate_data': 2,
    'set_ack': 3,
    'ping': 4,
    'wait_for_channels': 5,
    'disconnecting': 6,
    'notify': 7
}

# Main message types from server to client
server_main_num_to_str = copy.copy(server_common_num_to_str)
server_main_num_to_str.update({
    103: 'init',
    104: 'channels_list'
})

# Display message types from server to client
server_display_num_to_str = copy.copy(server_common_num_to_str)
server_display_num_to_str.update({
    101: 'mode',
    102: 'mark',
    103: 'reset',
    104: 'copy_bits',
    105: 'invalidate_list',
    106: 'invalidate_all_pixmaps',
    107: 'invalidate_palette',
    108: 'invalidate_all_palettes',

    122: 'stream_create',
    123: 'stream_data',
    124: 'stream_clip',
    125: 'stream_destroy',
    126: 'stream_destroy_all',

    302: 'draw_fill',
    303: 'draw_opaque',
    304: 'draw_copy',
    305: 'draw_blend',
    306: 'draw_blackness',
    307: 'draw_whiteness',
    308: 'draw_invers',
    309: 'draw_rop3',
    310: 'draw_stroke',
    311: 'draw_text',
    312: 'draw_transparent',
    313: 'draw_alpha_blend',
    314: 'surface_create',
    315: 'surface_destroy',
    316: 'stream_data_sized',
    317: 'monitors_config',
    318: 'draw_composite',
    319: 'stream_activate_report',
    320: 'gl_scanout_unix',
    321: 'gl_draw'
})

server_display_str_to_num = copy.copy(server_common_str_to_num)
server_display_str_to_num.update({
    'mode': 101,
    'mark': 102,
    'reset': 103,
    'copy_bits': 104,
    'invalidate_list': 105,
    'invalidate_all_pixmaps': 106,
    'invalidate_palette': 107,
    'invalidate_all_palettes': 108,

    'stream_create': 122,
    'stream_data': 123,
    'stream_clip': 124,
    'stream_destroy': 125,
    'stream_destroy_all': 126,

    'draw_fill': 302,
    'draw_opaque': 303,
    'draw_copy': 304,
    'draw_blend': 305,
    'draw_blackness': 306,
    'draw_whiteness': 307,
    'draw_invers': 308,
    'draw_rop3': 309,
    'draw_stroke': 310,
    'draw_text': 311,
    'draw_transparent': 312,
    'draw_alpha_blend': 313,
    'surface_create': 314,
    'surface_destroy': 315,
    'stream_data_sized': 316,
    'monitors_config': 317,
    'draw_composite': 318,
    'stream_activate_report': 319,
    'gl_scanout_unix': 320,
    'gl_draw': 321
})

# Input message types server to client
server_inputs_num_to_str = copy.copy(server_common_num_to_str)
server_inputs_num_to_str.update({
    101: 'init',
    102: 'key_modifiers',
    111: 'mouse_motion_ack'
})

# Cursor message types from server to client
server_cursor_num_to_str = copy.copy(server_common_num_to_str)
server_cursor_num_to_str.update({
    101: 'init',
    102: 'reset',
    103: 'set',
    104: 'move',
    105: 'hide',
    106: 'trail',
    107: 'invalidate_one',
    108: 'invalidate_all'
})

# Port (USB redirection) message types server to client
server_port_num_to_str = client_port_num_to_str

# Keyboard modifiers
keyboard_modifier_flags_scroll_lock = 1 << 0
keyboard_modifier_flags_num_lock = 1 << 1
keyboard_modifier_flags_caps_lock = 1 << 2

# Display channel raster operations
rasterop_inverse_src = 1 << 0
rasterop_inverse_brush = 1 << 1
rasterop_inverse_dest = 1 << 2
rasterop_put = 1 << 3
rasterop_or = 1 << 4
rasterop_and = 1 << 5
rasterop_xor = 1 << 6
rasterop_blackness = 1 << 7
rasterop_whiteness = 1 << 8
rasterop_inverse = 1 << 9
rasterop_inverse_result = 1 << 10

rasterops = [rasterop_inverse_src, rasterop_inverse_brush, rasterop_inverse_dest,
             rasterop_put, rasterop_or, rasterop_and, rasterop_xor,
             rasterop_blackness, rasterop_whiteness, rasterop_inverse,
             rasterop_inverse_result]

rasterops_num_to_str = {
    rasterop_inverse_src: 'inverse src',
    rasterop_inverse_brush: 'inverse brush',
    rasterop_inverse_dest: 'inverse dest',
    rasterop_put: 'put',
    rasterop_or: 'or',
    rasterop_and: 'and',
    rasterop_xor: 'xor',
    rasterop_blackness: 'blackness',
    rasterop_whiteness: 'whiteness',
    rasterop_inverse: 'inverse',
    rasterop_inverse_result: 'inverse result'
}

scale_mode_num_to_str = {
    0: 'interpolate',
    1: 'nearest'
}

scale_mode_str_to_num = {
    'interpolate': 0,
    'nearest': 1
}

image_type_num_to_str = {
    0: 'pixmap',
    1: 'quic',
    100: 'lz_palette',
    101: 'lz_rgb',
    102: 'glz_rgb',
    103: 'from_cache'
}

image_type_str_to_num = {
    'pixmap': 0,
    'quic': 1,
    'lz_palette': 100,
    'lz_rgb': 101,
    'glz_rgb': 102,
    'from_cache': 103
}

lz_max_copy = 32

lz_image_type_num_to_str = {
    0: 'invalid',
    1: 'palette1_le',
    2: 'palette1_be',
    3: 'palette4_le',
    4: 'palette4_be',
    5: 'palette8',
    6: 'rgb16',
    7: 'rgb24',
    8: 'rgb32',
    9: 'rgba',
    10: 'xxxa'
}

lz_image_type_str_to_num = {
    'invalid': 0,
    'palette1_le': 1,
    'palette1_be': 2,
    'palette4_le': 3,
    'palette4_be': 4,
    'palette8': 5,
    'rgb16': 6,
    'rgb24': 7,
    'rgb32': 8,
    'rgba': 9,
    'xxxa': 10
}

# Display channel clip types
display_clip_types_num_to_str = {
    0: 'none',
    1: 'rects',
    2: 'path'
}

display_clip_types_str_to_num = {
    'none': 0,
    'rects': 1,
    'path': 2
}

# Display brush types
display_brush_types_str_to_num = {
    'none': 0,
    'solid': 1,
    'pattern': 2
}

# USB redir protocol subpacket types. See these URLs for details:
# https://gitlab.freedesktop.org/spice/usbredir/-/blob/main/usbredirparser/usbredirproto.h
# https://gitlab.freedesktop.org/spice/usbredir/-/blob/main/docs/usb-redirection-protocol.md#usb_redir_hello
usb_redir_num_to_str = {
    # Control packets
    0: 'usb_redir_hello',
    1: 'usb_redir_device_connect',
    2: 'usb_redir_device_disconnect',
    3: 'usb_redir_reset',
    4: 'usb_redir_interface_info',
    5: 'usb_redir_ep_info',
    6: 'usb_redir_set_configuration',
    7: 'usb_redir_get_configuration',
    8: 'usb_redir_configuration_status',
    9: 'usb_redir_set_alt_setting',
    10: 'usb_redir_get_alt_setting',
    11: 'usb_redir_alt_setting_status',
    12: 'usb_redir_start_iso_stream',
    13: 'usb_redir_stop_iso_stream',
    14: 'usb_redir_iso_stream_status',
    15: 'usb_redir_start_interrupt_receiving',
    16: 'usb_redir_stop_interrupt_receiving',
    17: 'usb_redir_interrupt_receiving_status',
    18: 'usb_redir_alloc_bulk_streams',
    19: 'usb_redir_free_bulk_streams',
    20: 'usb_redir_bulk_streams_status',
    21: 'usb_redir_cancel_data_packet',
    22: 'usb_redir_filter_reject',
    23: 'usb_redir_filter_filter',
    24: 'usb_redir_device_disconnect_ack',
    25: 'usb_redir_start_bulk_receiving',
    26: 'usb_redir_stop_bulk_receiving',
    27: 'usb_redir_bulk_receiving_status',

    # Data packets
    100: 'usb_redir_control_packet',
    101: 'usb_redir_bulk_packet',
    102: 'usb_redir_iso_packet',
    103: 'usb_redir_interrupt_packet',
    104: 'usb_redir_buffered_bulk_packet'
}
