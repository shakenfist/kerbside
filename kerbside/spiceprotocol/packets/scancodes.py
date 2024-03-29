class RepeatedCodeException(Exception):
    ...


class ScanCodesPCAT(object):
    def __init__(self):
        self._codes = {}

    def _add_code(self, key, code, state):
        if code in self._codes:
            raise RepeatedCodeException(
                'Code 0x%02x already appears in the map' % code)

        self._codes[code] = (key, state)

    def add_code_set(self, key, code):
        self._add_code(key, code, 'down')
        self._add_code(key, code | (1 << 7), 'up')

    def lookup_code(self, code):
        return self._codes.get(code, ('unknown', 'unknown'))


scancodes = ScanCodesPCAT()

scancodes._add_code('error', 0x00, '')
keys = ['escape', '1!', '2@', '3#', '4$', '5%%', '6^', '7&', '8*', '9(', '0)',
        '-_', '=+', 'backspace', 'tab', 'q', 'w', 'e', 'r', 't', 'y', 'u',
        'i', 'o', 'p', '[{', ']}', 'enter', 'left control', 'a', 's', 'd', 'f',
        'g', 'h', 'j', 'k', 'l', ';:', '\'"', '`~', 'left shift', '\\|', 'z',
        'x', 'c', 'v', 'b', 'n', 'm', ',<', '.>', '/?', 'right shift',
        'print screen', 'left alt', 'space bar', 'caps lock', 'f1', 'f2', 'f3',
        'f4', 'f5', 'f6', 'f7', 'f8', 'f9', 'f10', 'num lock', 'scroll lock',
        'keypad-7/home', 'keypad-8/up', 'keypad-9/pgup', 'keypad--',
        'keypad-4/left', 'keypad-5', 'keypad-6/right', 'keypad-+',
        'keypad-1/end', 'keypad-2/down', 'keypad-3/pgdn', 'keypad-0/ins',
        'keypad-./del', 'alt-sysrq']

index = 1
for key in keys:
    scancodes.add_code_set(key, index)
    index += 1
