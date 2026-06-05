#!/bin/bash
# Gather diagnostic artifacts from an oVirt host for CI.
#
# This script runs on the oVirt target node. It collects RPM lists,
# download URLs, engine logs, VDSM logs, and SSH config into a zip
# bundle at /tmp/bundle.zip for upload as a CI artifact.

set -xe
export PS4='=======================\n+ '

# MIRROR_RPMS=1 also downloads each resolved RPM into /tmp/rpm-mirror so
# the bundle contains a self-contained package cache, not just URLs.
MIRROR_RPMS="${MIRROR_RPMS:-0}"

sudo rpm -qa --qf "%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n" \
    | grep -v '^gpg-pubkey' > /tmp/rpms.list

if [ "${MIRROR_RPMS}" = "1" ]; then
    sudo rm -rf /tmp/rpm-mirror
    sudo mkdir -p /tmp/rpm-mirror
fi

for rpm in $(cat /tmp/rpms.list); do
    echo "Caching URLs for ${rpm}"
    sudo yumdownloader --resolve --urls "${rpm}" \
        | egrep -v '(metadata expiration|Waiting for)' \
        >> /tmp/rpms.urls 2>/dev/null || true
    if [ "${MIRROR_RPMS}" = "1" ]; then
        echo "Downloading ${rpm} into mirror"
        sudo yumdownloader --resolve --destdir=/tmp/rpm-mirror "${rpm}" \
            >/dev/null 2>&1 || true
    fi
done

bundle_extra=()
if [ "${MIRROR_RPMS}" = "1" ]; then
    bundle_extra+=(/tmp/rpm-mirror)
fi

sudo zip -r /tmp/bundle.zip \
    /etc/yum.repos.d \
    /tmp/rpms.list \
    /tmp/rpms.urls \
    /var/lib/ovirt-engine/setup \
    /var/log/ovirt-engine/ \
    /var/log/vdsm/ \
    /etc/ssh/sshd_config.d/ \
    "${bundle_extra[@]}" \
    || true
sudo chmod ugo+r /tmp/bundle.zip
ls -lrth /tmp/bundle.zip
