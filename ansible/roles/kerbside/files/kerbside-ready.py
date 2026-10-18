#!/usr/bin/env python3
# Copyright 2026 Michael Still and contributors

"""Report whether Kerbside has fetched its Shaken Fist sources' signing keys.

Usage: kerbside-ready.py SOURCE_NAME...

Run with Kerbside's virtualenv Python by the kerbside role's register entry
point, with the name of every type shakenfist source in sources.yaml, and
polled until fetched_at is later than the time it recorded before restarting
Kerbside. Prints exactly one JSON object on stdout, for all the sources named:

    {"errored": false, "fetched_at": 1791234567.123}

* errored is true when any source's errored flag is set, null when any source
  has no row (and none is errored), and false otherwise. It is reported for
  diagnosis only: a new source is created with errored false before it has
  ever been scraped, and a failed key fetch deliberately does not set it, so
  it does not mean a source works.
* fetched_at is the oldest of the times Kerbside last stored each source's
  console token signing keys (a time.time() float), or null when it never has
  for at least one of them. So it is later than a given time only once every
  source named has fetched its keys since. Kerbside writes the keys only after
  the source's CA matched the one Shaken Fist serves and its credential
  authenticated, and refreshes the time on every successful scrape, which is
  what makes it the readiness signal. The keys row is never deleted, so its
  existence alone proves nothing about this deploy.
* error is present only when the database could not be read, with errored and
  fetched_at null. It names the exception's type and never its message, which
  can quote the database URL and so its password.

This reads Kerbside's internals, not a stable interface, and relies on these
identifiers in kerbside.db: the module-level ENGINE; the Source model's name
and errored columns; and the SfTokenKeys model's source and fetched_at
columns. They were checked against Kerbside v0.6.0 and develop at d0963ff. A
Kerbside which renamed or removed one fails the import or the query with an
AttributeError (or an ImportError, for a module which moved), and either is
reported as error, naming the type, like any other failure to read the
database: "importing kerbside.db failed: AttributeError" or "reading the
database failed: AttributeError". The register entry point's failure message
tells the operator that such an error means this script and the installed
Kerbside disagree, not that the CA or credential is wrong.

Nothing printed ever includes a key or a secret: the keys themselves and the
sources' credentials are never selected.

Importing kerbside.db reads /etc/kerbside/kerbside.ini (the path is fixed in
Kerbside) and prints its progress on stdout. On an INI it cannot parse,
Kerbside prints the parser's error, which can quote a line of the file, and
calls sys.exit(). The import's output is therefore captured and discarded, so
it never reaches stdout or the deploy log, and its SystemExit is caught and
reported as an error. The caller must still parse
stdout rather than trust the exit status: anything which is not this JSON
object means not ready.

Exits 0 whenever it printed the object, which includes not ready.
"""

import contextlib
import io
import json
import sys


def report(errored=None, fetched_at=None, error=None):
    out = {'errored': errored, 'fetched_at': fetched_at}
    if error:
        out['error'] = error
    print(json.dumps(out))


def load_db():
    """Import kerbside.db, or return the reason it could not be imported."""
    chatter = io.StringIO()
    try:
        with contextlib.redirect_stdout(chatter):
            from kerbside import db
        return db, None
    except SystemExit:
        return None, 'kerbside configuration did not load'
    except Exception as e:
        return None, 'importing kerbside.db failed: %s' % type(e).__name__


def read_state(db, source_name):
    """Return one source's errored flag and its keys' fetched_at, or None."""
    from sqlalchemy.orm import Session

    with Session(db.ENGINE) as session:
        source = session.query(db.Source.errored).filter(
            db.Source.name == source_name).one_or_none()
        keys = session.query(db.SfTokenKeys.fetched_at).filter(
            db.SfTokenKeys.source == source_name).one_or_none()

    errored = None if source is None or source[0] is None else bool(source[0])
    fetched_at = None if keys is None or keys[0] is None else float(keys[0])
    return errored, fetched_at


def combine(states):
    """Return the errored flag and fetched_at reported for several sources."""
    flags = [errored for errored, _ in states]
    times = [fetched_at for _, fetched_at in states]
    if True in flags:
        errored = True
    elif None in flags:
        errored = None
    else:
        errored = False
    fetched_at = None if None in times else min(times)
    return errored, fetched_at


def main(argv):
    if len(argv) < 2:
        report(error='usage: kerbside-ready.py SOURCE_NAME...')
        return 2

    db, error = load_db()
    if error:
        report(error=error)
        return 0

    try:
        errored, fetched_at = combine(
            [read_state(db, name) for name in argv[1:]])
    except Exception as e:
        report(error='reading the database failed: %s' % type(e).__name__)
        return 0

    report(errored=errored, fetched_at=fetched_at)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
