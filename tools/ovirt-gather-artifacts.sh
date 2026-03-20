#!/bin/bash
# Gather diagnostic artifacts from an oVirt host for CI.
#
# This script runs on the oVirt target node. It collects RPM lists,
# download URLs, engine logs, VDSM logs, and SSH config into a zip
# bundle at /tmp/bundle.zip for upload as a CI artifact.

set -xe
export PS4='=======================\n+ '

sudo rpm -qa --qf "%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n" \
    | grep -v '^gpg-pubkey' > /tmp/rpms.list

for rpm in $(cat /tmp/rpms.list); do
    echo "Caching URLs for ${rpm}"
    sudo yumdownloader --resolve --urls "${rpm}" \
        | egrep -v '(metadata expiration|Waiting for)' \
        >> /tmp/rpms.urls 2>/dev/null || true
done

sudo zip -r /tmp/bundle.zip \
    /etc/yum.repos.d \
    /tmp/rpms.list \
    /tmp/rpms.urls \
    /var/lib/ovirt-engine/setup \
    /var/log/ovirt-engine/ \
    /var/log/vdsm/ \
    /etc/ssh/sshd_config.d/ \
    || true
sudo chmod ugo+r /tmp/bundle.zip
ls -lrth /tmp/bundle.zip
