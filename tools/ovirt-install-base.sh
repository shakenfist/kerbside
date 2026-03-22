#!/bin/bash
# Install base packages on an oVirt target node for CI.
#
# This script runs on the oVirt target node. It installs EPEL,
# enables powertools/CRB, and installs basic utilities.
#
# Usage: ovirt-install-base.sh

set -xe
export PS4='=======================\n+ '

sudo dnf clean all
sudo dnf update -y
sudo dnf install -y epel-release
sudo dnf config-manager --set-enabled powertools 2>/dev/null \
    || sudo crb enable
sudo dnf clean all
sudo dnf update -y
sudo dnf install -y vim patch yum-utils
