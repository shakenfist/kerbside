# kerbside-tempest-plugin

A Tempest plugin that exercises the Kerbside SPICE VDI proxy as deployed
in front of Nova by Kolla-Ansible.

This is a separate releasable that lives in the [Kerbside repository](
https://github.com/shakenfist/kerbside) and shares Kerbside's version
number via `setuptools_scm` pointed at the repository root. Installing
the plugin into a Tempest virtualenv contributes one or more tests
under `kerbside_tempest_plugin.tests.api` and registers a `[kerbside]`
configuration group.

## Installing

From a Kerbside checkout:

```
pip install ./tempest-plugin
```

Or directly from git:

```
pip install "git+https://github.com/shakenfist/kerbside.git@<ref>#subdirectory=tempest-plugin&egg=kerbside-tempest-plugin"
```

## Configuration

```
[kerbside]
# Path to the CA bundle used to verify the HTTPS endpoint Nova returns
# in its remote-console URL. Typically the Kolla-Ansible root CA.
ca_cert_path = /etc/kolla/certificates/ca/root.crt

# The Sextant scenario test only runs when these are set, which the
# direct-qemu lane does and the OpenStack lane does not (see below).
#control_socket_path = /path/to/ryll-control.sock
#serial_log_path = /path/to/sextant-serial.log
#scenario_artifact_dir = /path/to/screenshots
#scenario_step_timeout = 60
```

API tests skip themselves if `compute-feature-enabled.spice_console`
is False.

## Tests

* `kerbside_tempest_plugin.tests.api.test_spice_via_kerbside`
  Creates an instance, requests a SPICE remote console via Nova, follows
  the returned URL to fetch the `.vv` file Kerbside serves, then opens
  a TLS connection to the Kerbside SPICE proxy and completes a minimal
  SPICE link handshake. This verifies the haproxy/Kerbside front-end is
  answering as SPICE; it does not (yet) authenticate and route through
  to a hypervisor console.

* `kerbside_tempest_plugin.tests.scenario.test_sextant_scenario`
  A full end-to-end proxied console session, backed by
  [ryll](https://github.com/shakenfist/ryll) and
  [uncalibrated-sextant](https://github.com/shakenfist/uncalibrated-sextant).
  It consumes an already-running direct-qemu lane (see
  `tools/direct-qemu/lane-up.sh`): a Sextant guest under qemu/KVM,
  fronted by Kerbside's SPICE proxy, with a headless ryll attached via
  the `.vv` file fetched from the Kerbside REST API. The test drives
  the canonical Sextant sequence (Awaiting -> Booting ->
  locked-bootloader Ignore -> paste -> Parked -> shutdown) over ryll's
  control socket and asserts the run against both the live QR digest
  stream and the post-mortem serial drain. It provisions nothing and
  never touches a cloud (no credentials, no keystone), skips unless
  `[kerbside] control_socket_path` is set, and is deliberately
  destructive -- the final keypress shuts the guest down -- so it must
  run as the last step on a lane.

## Roadmap

The Sextant scenario currently runs only on the direct-qemu lane. A
future test will drive the same full proxied console session on a real
OpenStack cloud, using the auth token from the `.vv` file that Nova's
remote-console URL leads to, so the end-to-end path is exercised
against a hypervisor managed by Nova rather than a lane-local qemu.
