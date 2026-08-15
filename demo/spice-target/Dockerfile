# A real SPICE server for the demo to proxy.
#
# A demo that proxies a fake SPICE server proves nothing, so this runs
# an actual qemu. It has no disk: with no bootable device SeaBIOS draws
# its "No bootable device" screen, which is a genuine SPICE display
# surface and exercises the whole path. That black screen with BIOS text
# IS the expected result of the demo.
#
# Debian plus one apt package, rather than a purpose-built qemu image:
# it is auditable in five lines and matches how the direct-qemu CI lane
# installs qemu. The cost is image size, which is the right trade in a
# directory whose value is that you can read what it does.

FROM debian:trixie-slim

# qemu-system-modules-spice is not optional here, and it is not pulled
# in by qemu-system-x86. Debian trixie moved SPICE out into a module
# package, so without it qemu starts and then dies with "There is no
# option group 'spice'". The direct-qemu CI lane does not hit this
# because its runner installs qemu from an older Debian where SPICE was
# built in. --no-install-recommends is what makes the split visible:
# the module is a Recommends of qemu-system-x86, not a Depends.
RUN apt-get update && apt-get install -y --no-install-recommends \
        qemu-system-x86 \
        qemu-system-modules-spice \
    && rm -rf /var/lib/apt/lists/*

# No accel=kvm. TCG is fine for a BIOS screen, so the demo needs no
# /dev/kvm and no privileged container, and runs on a laptop, in a VM,
# and in CI alike. Do not add conditional acceleration: it is complexity
# for no visible gain at a BIOS prompt.
#
# The ticket goes in via `-object secret` and `password-secret=`, NOT
# the inline `password=` parameter. The inline form was removed in newer
# qemu and fails outright on qemu 10 with "Invalid parameter
# 'password'"; `password-secret` has been supported since qemu 5.2, so
# this form works on the debian-12 CI runner and on a modern developer
# host alike. tools/direct-qemu/start-qemu.sh carries the same note,
# written after this project hit it.
#
# -vga qxl matches start-qemu.sh: it is the conventional SPICE display
# device, rather than relying on the q35 default.
CMD ["qemu-system-x86_64", \
     "-machine", "q35", \
     "-m", "256", \
     "-vga", "qxl", \
     "-object", "secret,id=spice-ticket,data=demo-ticket", \
     "-spice", "port=5910,password-secret=spice-ticket,disable-ticketing=off,addr=0.0.0.0", \
     "-display", "none"]

EXPOSE 5910
