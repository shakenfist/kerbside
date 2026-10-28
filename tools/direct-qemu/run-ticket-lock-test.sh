#!/bin/bash
# Prove on MariaDB that concurrent channels of one session mint its backend
# ticket once (kerbside/tests/functional/test_session_ticket_lock.py), and
# that the longest values a source driver produces fit their columns
# (kerbside/tests/functional/test_column_widths.py).
#
# SQLite ignores SELECT ... FOR UPDATE, and a VARCHAR's length, so the unit
# tests cannot show either. The lane's MariaDB is the nearest real engine.
# Each module drops and recreates its own database, kerbside_locktest, one
# after the other, and drops it again when it finishes, so the kerbside
# database the lane's daemon uses is never touched. This script grants the
# kerbside user (created by setup-mariadb.sh, which must run first) every
# privilege on kerbside_locktest, which is what lets the tests create and
# drop it.
#
# The tests run from the checkout with the kerbside venv's interpreter. The
# wheel installed there leaves the tests out, and python -m puts the current
# directory first on sys.path, so the checkout's kerbside is the one tested.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "${REPO_ROOT}"

VENV="${KERBSIDE_VENV:-/tmp/kerbside-venv}"
DB_NAME='kerbside_locktest'
DB_USER='kerbside'
DB_PASS='kerbside'
TEST_TIMEOUT="${TEST_TIMEOUT:-300}"

drop_database() {
    sudo mysql -e "DROP DATABASE IF EXISTS ${DB_NAME};"
}

echo "[ticket-lock] Granting ${DB_USER}@localhost all privileges on ${DB_NAME}"
sudo mysql <<SQL
GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'localhost';
FLUSH PRIVILEGES;
SQL

# The test drops its database itself; this also covers a run killed by the
# timeout before its cleanup ran.
trap drop_database EXIT

echo "[ticket-lock] Running the session ticket lock and column width tests"
KERBSIDE_TEST_SQL_URL="mysql://${DB_USER}:${DB_PASS}@127.0.0.1/${DB_NAME}" \
    timeout "${TEST_TIMEOUT}" "${VENV}/bin/python3" -m unittest -v \
    kerbside.tests.functional.test_session_ticket_lock \
    kerbside.tests.functional.test_column_widths

echo "[ticket-lock] Done"
