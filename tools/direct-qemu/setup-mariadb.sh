#!/bin/bash
# Initialize MariaDB for the kerbside direct-qemu CI lane.
#
# Debian's mariadb-server package starts the daemon on install and
# configures unix_socket auth for the root user, so `sudo mysql` works
# without a password.  This script (idempotently) creates the kerbside
# database and a kerbside user with a fixed CI password.

set -euo pipefail

DB_NAME='kerbside'
DB_USER='kerbside'
DB_PASS='kerbside'

echo "[setup-mariadb] Ensuring mariadb is running"
sudo systemctl start mariadb

echo "[setup-mariadb] Creating database ${DB_NAME} and user ${DB_USER}@localhost"
sudo mysql <<SQL
CREATE DATABASE IF NOT EXISTS ${DB_NAME};
CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';
GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'localhost';
FLUSH PRIVILEGES;
SQL

echo "[setup-mariadb] Done"
