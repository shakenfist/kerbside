import datetime


LOGFILE = None


def _log(thread_name, msg, severity=''):
    global LOGFILE
    if not LOGFILE:
        LOGFILE = open('logfile', 'w')

    printable = f'{datetime.datetime.now()} [{thread_name:10s}] {severity.upper():7s} {msg}'
    LOGFILE.write(printable)
    LOGFILE.write('\n')

    if severity == 'debug':
        return

    print(printable)
