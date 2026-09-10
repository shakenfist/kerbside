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
