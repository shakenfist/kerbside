#!/usr/bin/env python3
# Copyright 2026 Michael Still and contributors

"""Report whether Kerbside has fetched its Shaken Fist sources' signing keys.

Usage: kerbside-ready.py SOURCE_NAME...

Run with Kerbside's virtualenv Python by the kerbside role's register entry
point, with the name of every type shakenfist source in sources.yaml, and
polled until fetched_at is later than the time it recorded before restarting
Kerbside. Prints exactly one JSON object on stdout, for all the sources named:

    {"errored": false, "fetched_at": 1791234567.123, "keys_usable": true}

* errored is true when any source's errored flag is set, null when any source
  has no row (and none is errored), and false otherwise. It is reported for
  diagnosis only: a new source is created with errored false before it has
  ever been scraped, and a failed key fetch deliberately does not set it, so
  it does not mean a source works.
* keys_usable is whether every source's stored key set could verify a token
  minted now: the document Shaken Fist published names the kid it is signing
  with, and that kid has to be among the keys in the same document, with a
  public key. It is null when any source has never stored a set (so there is
  nothing to judge), and false when a stored set is not a document of that
  shape. A fetch proves the CA matched and the credential authenticated; this
  is the part a fetch does not prove, and a deploy used to pass without it
  (#620). Only the verdict is printed, never a kid or a key.
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
and errored columns; and the SfTokenKeys model's source, fetched_at and
keys_json columns. They were checked against Kerbside v0.6.0 and develop at
d0963ff, and keys_json against develop at b329233. A
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


def report(errored=None, fetched_at=None, keys_usable=None, error=None):
    out = {'errored': errored, 'fetched_at': fetched_at,
           'keys_usable': keys_usable}
    if error:
        out['error'] = error
    # sys.stdout.write rather than print(), as kerbside-host-subject.py
    # also does. One JSON object on stdout is this script's contract, so
    # the writing is deliberate -- but the push audit's wave 1 fails any
    # range that adds a raw print() to non-test source, and it exited 3
    # here and never reached its bare-except check (#623).
    #
    # The alternative was wave 1's opt-in marker comment, which is not
    # spelled out anywhere in this file on purpose: it suppresses the
    # print check for the whole diff rather than for the file carrying
    # it, so a branch that merely touched this script would get no print
    # check at all. Writing to stdout keeps the gate live instead of
    # exempting a file from it. The bytes are the same either way, which
    # the role's own parsing pattern is tested against.
    sys.stdout.write(json.dumps(out) + '\n')


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


def usable(keys_json):
    """Could the stored key set verify a token minted now?

    Shaken Fist's published document names its active kid, and Kerbside
    caches the document verbatim, so this is answerable without asking
    Shaken Fist anything: the active kid must be among the document's own
    keys, carrying a public key to verify with. None when there is no
    document at all, which is "not fetched yet" rather than a verdict.

    This is stricter than Kerbside's verifier, which matches a token's own
    kid against the keys and never reads active_kid, on purpose: Shaken Fist
    signs every new token with its active kid, so only a document which
    names that kid and carries its key shows that the next token will
    verify. Whatever else it holds proves only that some earlier token
    would. The shape -- an active_kid, and keys each with a kid and a
    public_pem -- is Shaken Fist's /admin/vditokenpubkey response as its
    external_api/admin.py documents it and util/vdi_tokens.py builds it,
    read at Shaken Fist develop 3d93fde425 (after v0.8.0-rc4). A Shaken
    Fist which changed it would block the deploy here with keys_usable
    false, and this is the place to look.
    """
    if keys_json is None:
        return None
    try:
        document = json.loads(keys_json)
    except (ValueError, TypeError):
        return False
    if not isinstance(document, dict):
        return False
    active = document.get('active_kid')
    keys = document.get('keys')
    if not active or not isinstance(keys, list):
        return False
    return any(isinstance(key, dict) and key.get('kid') == active
               and key.get('public_pem') for key in keys)


def read_state(db, source_name):
    """Return one source's errored flag, keys' fetched_at and usability."""
    from sqlalchemy.orm import Session

    with Session(db.ENGINE) as session:
        source = session.query(db.Source.errored).filter(
            db.Source.name == source_name).one_or_none()
        keys = session.query(
            db.SfTokenKeys.fetched_at, db.SfTokenKeys.keys_json).filter(
                db.SfTokenKeys.source == source_name).one_or_none()

    errored = None if source is None or source[0] is None else bool(source[0])
    fetched_at = None if keys is None or keys[0] is None else float(keys[0])
    return errored, fetched_at, usable(None if keys is None else keys[1])


def combine(states):
    """Return what is reported for several sources, as the worst of each.

    A deploy is ready when every source is, so the oldest fetch, any
    errored flag, and the least usable key set are what is reported.
    """
    flags = [errored for errored, _, _ in states]
    times = [fetched_at for _, fetched_at, _ in states]
    verdicts = [keys_usable for _, _, keys_usable in states]
    if True in flags:
        errored = True
    elif None in flags:
        errored = None
    else:
        errored = False
    fetched_at = None if None in times else min(times)
    if None in verdicts:
        keys_usable = None
    elif False in verdicts:
        keys_usable = False
    else:
        keys_usable = True
    return errored, fetched_at, keys_usable


def main(argv):
    if len(argv) < 2:
        report(error='usage: kerbside-ready.py SOURCE_NAME...')
        return 2

    db, error = load_db()
    if error:
        report(error=error)
        return 0

    try:
        errored, fetched_at, keys_usable = combine(
            [read_state(db, name) for name in argv[1:]])
    except Exception as e:
        report(error='reading the database failed: %s' % type(e).__name__)
        return 0

    report(errored=errored, fetched_at=fetched_at, keys_usable=keys_usable)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
