import os
import yaml

from .config import config


def configure_logging():
    # Parse our configuration options and return a set of kwargs which can be
    # passed to logs.setup(). Note that daemon logs are always structured
    # JSON -- shakenfist_utilities removed its text formatter in v0.8.5 --
    # so there is no output format to configure here.
    out = {
        'syslog': True,
        'logpath': ''
    }

    if config.LOG_OUTPUT_PATH:
        out['syslog'] = False
        out['logpath'] = config.LOG_OUTPUT_PATH

    print(f'PID {os.getpid()} logging configured: {out}')
    return out


# sources.yaml is written by hand, and YAML 1.1 types an unquoted scalar
# by its spelling. A ticket written as 012345 is octal and arrives as the
# int 5349, 0x1F as 31, 1_000 as 1000 and 12:34 as 754: converting the
# int back to a string cannot recover what the operator wrote, so the
# SPICE password silently stops matching qemu's. load_sources() is the
# one way kerbside reads the file, and it resolves no numbers or dates at
# all, so every such scalar arrives as the text it spells; only true,
# false and null keep their types. A field which is a number says so in
# its normaliser.
#
# The database hands back each column's type, so a value kept in YAML's
# type would never compare equal to what was stored, and every
# maintenance pass would rewrite and audit it as changed. The normalisers
# below turn a hand-written scalar into the type its column stores, and
# raise YAMLScalarError for anything else -- a list, a mapping, a bool,
# or a port that is not one.

_SPELLED_TAGS = ('tag:yaml.org,2002:int', 'tag:yaml.org,2002:float',
                 'tag:yaml.org,2002:timestamp')


class _SourcesLoader(yaml.SafeLoader):
    """A SafeLoader which leaves numbers and dates as the text written."""


# A filtered copy: SafeLoader's own table is shared by every
# yaml.safe_load() in the process, and must not change.
_SourcesLoader.yaml_implicit_resolvers = {
    first: [(tag, regexp) for tag, regexp in resolvers
            if tag not in _SPELLED_TAGS]
    for first, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}


def load_sources(stream):
    """Parse sources.yaml, keeping every number as the text it spells."""
    return yaml.load(stream, Loader=_SourcesLoader)


class YAMLScalarError(ValueError):
    """A hand-written scalar is not a spelling of its field's value.

    The message says what the field must be and never quotes the value,
    which may be a password.
    """


def yaml_string(value):
    """Return a hand-written YAML scalar as the string it spells."""
    # Not int: load_sources() never produces one, and a caller which
    # parsed the file some other way has already lost the spelling.
    if not isinstance(value, str):
        raise YAMLScalarError(
            'must be text, not %s' % type(value).__name__)
    return value


def yaml_port(value):
    """Return a hand-written YAML scalar as the port number it spells."""
    # isdecimal() alone admits other scripts' digits, which int() reads.
    if isinstance(value, str):
        if not (value.isascii() and value.isdecimal()):
            raise YAMLScalarError('must be a port number from 1 to 65535')
        value = int(value)
    elif isinstance(value, bool) or not isinstance(value, int):
        raise YAMLScalarError(
            'must be a port number, not %s' % type(value).__name__)
    if not 1 <= value <= 65535:
        raise YAMLScalarError('must be a port number from 1 to 65535')
    return value
