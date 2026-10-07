import os

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


# sources.yaml is written by hand, and YAML types an unquoted scalar by
# its spelling: a password written as 123456 arrives as an int, and a
# port written as "5900" arrives as a str. The database hands back the
# column's type, so a value kept in YAML's type never compares equal to
# what was stored, and every maintenance pass would rewrite and audit it
# as changed. These normalise a hand-written scalar to the type its
# column stores. Anything else -- a list, a mapping, a bool, a float --
# is not a spelling of the value, and raises TypeError naming only the
# type, never the value, since the value may be a password.

def yaml_string(value):
    """Return a hand-written YAML scalar as the string it spells."""
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise TypeError(type(value).__name__)
    return str(value)


def yaml_port(value):
    """Return a hand-written YAML scalar as the port number it spells."""
    if isinstance(value, bool):
        raise TypeError(type(value).__name__)
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    raise TypeError(type(value).__name__)
