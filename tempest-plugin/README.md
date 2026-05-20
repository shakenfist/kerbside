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
```

Tests skip themselves if `compute-feature-enabled.spice_console` is False.

## Tests

* `kerbside_tempest_plugin.tests.api.test_spice_via_kerbside`
  Creates an instance, requests a SPICE remote console via Nova, follows
  the returned URL to fetch the `.vv` file Kerbside serves, then opens
  a TLS connection to the Kerbside SPICE proxy and completes a minimal
  SPICE link handshake. This verifies the haproxy/Kerbside front-end is
  answering as SPICE; it does not (yet) authenticate and route through
  to a hypervisor console.

## Roadmap

A future test will use the auth token from the `.vv` file to drive a
full proxied console session through to a hypervisor, eventually backed
by [ryll](https://github.com/shakenfist/ryll) and
[uncalibrated-sextant](https://github.com/shakenfist/uncalibrated-sextant)
to walk the SPICE protocol end to end.
