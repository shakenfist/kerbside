#!/usr/bin/env python3
# Copyright 2026 Michael Still and contributors

"""Check a rendered kerbside.ini before it replaces the running one.

Usage: kerbside-check-ini.py KERBSIDE.ini

A kerbside.ini Kerbside cannot parse stops it at start: it prints the error
and exits non-zero, so under systemd the service restarts forever. The role
therefore runs this as the template task's validate command, so a file
Kerbside could not read is refused and the old one stays in place.

The file is read the way kerbside/config.py reads it, with interpolation off,
so a % in a value is literal, exactly as Kerbside will see it, and every value
in the [kerbside] section is then fetched. A value which spans lines is refused
too: configparser would accept it, but no Kerbside setting is multi-line, so it
means a value carried a newline the role did not expect.

The file holds secrets, so no message here ever includes a value, or the text
of a line (which configparser's own messages do). Messages name the option or
the line number instead.

Exits 0 when the file is good, and 1 with the reasons on stderr when it is not.
"""

import configparser
import sys


SECTION = 'kerbside'


def make_parser():
    """Return a parser which reads the file as Kerbside's config.py does."""
    return configparser.ConfigParser(interpolation=None)


def check(path):
    """Return a list of reasons path is not a good kerbside.ini."""
    parser = make_parser()
    # Only the type and line number of an error are reported: configparser's
    # own messages quote the offending line. MissingSectionHeaderError is a
    # ParsingError with a line number but no list of errors, so the list is
    # read only where there is one.
    try:
        read = parser.read(path)
    except configparser.Error as e:
        linenos = [lineno for lineno, _ in getattr(e, 'errors', [])]
        if not linenos and getattr(e, 'lineno', None):
            linenos = [e.lineno]
        if not linenos:
            return ['%s' % type(e).__name__]
        return ['%s at line %d' % (type(e).__name__, lineno)
                for lineno in linenos]
    except UnicodeDecodeError as e:
        return ['the file is not valid text in the locale\'s encoding (%s)'
                % e.reason]
    except Exception as e:
        return ['the file could not be read: %s' % type(e).__name__]

    if not read:
        return ['the file could not be read']
    if not parser.has_section(SECTION):
        return ['the file has no [%s] section' % SECTION]

    errors = []
    for option in parser.options(SECTION):
        try:
            value = parser.get(SECTION, option)
        except configparser.Error as e:
            errors.append('%s cannot be read: %s' % (option, type(e).__name__))
            continue
        if '\n' in value:
            errors.append('%s spans more than one line' % option)
    return errors


def main(argv):
    if len(argv) != 2:
        sys.stderr.write('usage: %s KERBSIDE.ini\n' % argv[0])
        return 2

    errors = check(argv[1])
    for error in errors:
        sys.stderr.write('kerbside.ini refused: %s\n' % error)
    return 1 if errors else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
