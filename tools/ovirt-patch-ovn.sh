#!/bin/bash
# Patch the oVirt host-deploy OVN Ansible role (oVirt/ovirt-engine#949).
#
# This script runs on the oVirt target node. It fixes a bug in oVirt 4.5
# where the OVN configuration task runs even when OVN is not configured
# on the cluster. The broken condition "ovn_central is defined" fires
# when ovn_central is None/empty. The fix adds proper None/length checks.

set -xe
export PS4='=======================\n+ '

OVN_CFG=/usr/share/ovirt-engine/ansible-runner-service-project
OVN_CFG=${OVN_CFG}/project/roles/ovirt-provider-ovn-driver
OVN_CFG=${OVN_CFG}/tasks/configure.yml

sudo sed -i \
    's/ovn_central is defined$/ovn_central is defined and ovn_central != None and ovn_central | length != 0/' \
    "$OVN_CFG"

echo '--- Patched OVN configure.yml ---'
grep -n 'ovn_central' "$OVN_CFG"
