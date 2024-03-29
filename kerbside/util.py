from .config import config


def configure_logging():
    # Parse our configuration options and return a set of kwargs which can be
    # passed to logs.setup().
    out = {
        'syslog': True,
        'logpath': '',
        'json': False
    }

    if config.LOG_OUTPUT_PATH:
        out['syslog'] = False
        out['logpath'] = config.LOG_OUTPUT_PATH

    if config.LOG_OUTPUT_JSON:
        out['json'] = True

    return out
