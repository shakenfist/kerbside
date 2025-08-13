#!/bin/bash

test_image="uefi-latency-guest"
test_flavor="vdi"
test_identifier=$$

for id in $(openstack server list -f json | \
    jq -e -r '.[] | select(.Name!="uefi-latency-guest") | .ID'); do
    echo "Deleting ID ${id}"
    openstack server delete "${id}"
done