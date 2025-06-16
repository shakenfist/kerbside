import datetime


LOGFILE = None
LOGFILE_PATH = None


def _log(thread_name, msg, severity=''):
    global LOGFILE
    if not LOGFILE:
        logfile_path = LOGFILE_PATH
        if not logfile_path:
            logfile_path = 'logfile'
        LOGFILE = open(LOGFILE_PATH, 'w')

    printable = f'{datetime.datetime.now()} [{thread_name:10s}] {severity.upper():7s} {msg}'
    LOGFILE.write(printable)
    LOGFILE.write('\n')

    if severity == 'debug':
        return

    print(printable)
