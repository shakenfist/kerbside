#!/bin/bash

# Installs any project-specific apt packages the pin-indirect-dependencies
# workflow needs on top of the baseline it installs itself (git,
# python3-dev, python3-pip, python3-venv, python3-wheel, curl).
#
# Reads tools/pin-indirect-dependencies-apt.txt in the current directory,
# one package name per line, blank lines and "#" comments ignored, and
# anything else that is not a Debian package name rejected. A
# project with nothing extra to install has no reason to carry the file,
# so its absence is not an error: this script does nothing and exits zero.
#
# Runs after the target repository is checked out, and from inside it,
# because the file it reads lives there rather than in the workflow's own
# checkout.
#
# Template source:
#   https://github.com/shakenfist/development/tree/main/templates/pin-indirect-dependencies/

set -euo pipefail

apt_file="tools/pin-indirect-dependencies-apt.txt"

if [ ! -f "${apt_file}" ]; then
    echo "No ${apt_file}, nothing extra to install."
    exit 0
fi

mapfile -t packages < <(grep -v '^[[:space:]]*#' "${apt_file}" | grep -v '^[[:space:]]*$' || true)

if [ "${#packages[@]}" -eq 0 ]; then
    echo "${apt_file} exists but names no packages."
    exit 0
fi

# Each entry must look like a Debian package name, so a stray line
# beginning with "-" cannot turn into an apt-get option. The names are
# also passed after "--" below, as a second line of defence.
for package in "${packages[@]}"; do
    if ! [[ "${package}" =~ ^[a-z0-9][a-z0-9+.-]*$ ]]; then
        echo "${apt_file}: '${package}' is not a package name." >&2
        exit 1
    fi
done

echo "Installing extra packages from ${apt_file}:"
printf '%s\n' "${packages[@]}"

sudo apt update
# The lock-timeout and confold options match every other apt call in
# this workflow: a bare "apt install" on an ephemeral vm that boots into
# an unattended-upgrades window either fails on the dpkg lock or hangs
# on a conffile prompt.
sudo DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=-1 -o Dpkg::Options::="--force-confold" -y \
    install -- "${packages[@]}"
