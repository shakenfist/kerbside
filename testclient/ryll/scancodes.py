# Keyboard scancodes in SPICE are honestly a bit of a mess. They're nominally PCAT, but that's
# so old that its not entirely clear _which_ version of the keyboard we're talking about. If
# you're into non-ASCII characters, you're probably better off passing through a USB device
# that doing this thing.
#
# Just to add to the fun, we're trying to make tkinter keysyms into scan codes here.

def _generate_down_and_release(keycode):
    return (keycode, keycode | 1 << 7)


# AT-84 keys ala https://telcontar.net/KBK/Hi-Tek/docs/Hi-Tek%20AT-84%20Keyboards%20(1984).pdf
at_84 = {
    9: _generate_down_and_release(1),       # Escape
    67: _generate_down_and_release(58),     # F1
    68: _generate_down_and_release(59),     # F2
    69: _generate_down_and_release(60),     # F3
    70: _generate_down_and_release(61),     # F4
    71: _generate_down_and_release(62),     # F5
    72: _generate_down_and_release(63),     # F6
    73: _generate_down_and_release(64),     # F7
    74: _generate_down_and_release(65),     # F8
    75: _generate_down_and_release(66),     # F9
    76: _generate_down_and_release(67),     # F10
                                            # F11
                                            # F12

    49: _generate_down_and_release(41),     # `~
    10: _generate_down_and_release(2),      # 1!
    11: _generate_down_and_release(3),      # 2@
    12: _generate_down_and_release(4),      # 3#
    13: _generate_down_and_release(5),      # 4$
    14: _generate_down_and_release(6),      # 5%
    15: _generate_down_and_release(7),      # 6^
    16: _generate_down_and_release(8),      # 7&
    17: _generate_down_and_release(9),      # 8*
    18: _generate_down_and_release(10),     # 9(
    19: _generate_down_and_release(11),     # 0)
    20: _generate_down_and_release(12),     # -_
    21: _generate_down_and_release(13),     # =+
    22: _generate_down_and_release(14),     # BackSpace

    23: _generate_down_and_release(15),     # Tab
    24: _generate_down_and_release(16),     # q
    25: _generate_down_and_release(17),     # w
    26: _generate_down_and_release(18),     # e
    27: _generate_down_and_release(19),     # r
    28: _generate_down_and_release(20),     # t
    29: _generate_down_and_release(21),     # y
    30: _generate_down_and_release(22),     # u
    31: _generate_down_and_release(23),     # i
    32: _generate_down_and_release(24),     # o
    33: _generate_down_and_release(25),     # p
    34: _generate_down_and_release(26),     # [{
    35: _generate_down_and_release(27),     # ]}
    51: _generate_down_and_release(42),     # \|

    66: _generate_down_and_release(57),     # Caps Lock
    38: _generate_down_and_release(30),     # a
    39: _generate_down_and_release(31),     # s
    40: _generate_down_and_release(32),     # d
    41: _generate_down_and_release(33),     # f
    42: _generate_down_and_release(34),     # g
    43: _generate_down_and_release(35),     # h
    44: _generate_down_and_release(36),     # j
    45: _generate_down_and_release(37),     # k
    46: _generate_down_and_release(38),     # l
    47: _generate_down_and_release(39),     # ;:
    48: _generate_down_and_release(40),     # '"
    36: _generate_down_and_release(28),     # Enter (Return)

    50: _generate_down_and_release(41),     # Left Shift
    52: _generate_down_and_release(44),     # z
    53: _generate_down_and_release(45),     # x
    54: _generate_down_and_release(46),     # c
    55: _generate_down_and_release(47),     # v
    56: _generate_down_and_release(48),     # b
    57: _generate_down_and_release(49),     # n
    58: _generate_down_and_release(50),     # m
    59: _generate_down_and_release(51),     # ,<
    60: _generate_down_and_release(52),     # .>
    61: _generate_down_and_release(53),     # /?
    62: _generate_down_and_release(54),     # Right Shift

    37: _generate_down_and_release(29),     # Left Control
                                            # Windows key is eaten by the window manager
    64: _generate_down_and_release(55),     # Left Alt
    65: _generate_down_and_release(57),     # Spacebar
                                            # Right Alt
                                            # Fn is a meta key
                                            # Right Control

                                            # Print Screen is eaten by the window manager (AT code 54)
    78: _generate_down_and_release(69),     # Scroll Lock
                                            # Pause

                                            # Insert
                                            # Home
                                            # PgUp

                                            # Del
                                            # End
                                            # PgDown

    127: _generate_down_and_release(68),    # NumLock

    # 'keypad-7/home': _generate_down_and_release(70),
    # 'keypad-8/up': _generate_down_and_release(1),
    # 'keypad-9/pgup': _generate_down_and_release(1),
    # 'keypad--',
    # 'keypad-4/left': _generate_down_and_release(1),
    # 'keypad-5': _generate_down_and_release(1),
    # 'keypad-6/right': _generate_down_and_release(1),
    # 'keypad-+',
    # 'keypad-1/end': _generate_down_and_release(1),
    # 'keypad-2/down': _generate_down_and_release(1),
    # 'keypad-3/pgdn': _generate_down_and_release(1),
    # 'keypad-0/ins',
    # 'keypad-./del': _generate_down_and_release(1),
    # 'alt-sysrq'
}
