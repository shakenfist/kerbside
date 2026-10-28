---
name: add-source-type
description: Add a new cloud console source to Kerbside, from the source class through registration, tests and documentation. Use when wiring Kerbside up to a cloud platform it does not discover consoles from yet.
---

# Add New Cloud Source Type

When adding a new cloud source type to Kerbside:

1. Create a new file in `kerbside/sources/` following the pattern of
   existing sources (`shakenfist.py`, `ovirt.py`).

2. Inherit from `BaseSource` in `kerbside/sources/base.py`.

3. Implement the `__call__()` method to yield console entries as dicts
   with keys: `source`, `uuid`, `name`, `hypervisor`, `hypervisor_ip`,
   `insecure_port`, `secure_port` and `host_subject`. A driver which
   cannot name a dialable address yields empty `hypervisor_ip` and `None`
   ports (see `sources/proxmox.py`). Raise from `__call__()` when the
   source cannot be enumerated at all, so that it is marked errored and
   keeps its consoles; skip a single console that cannot be read.

4. Implement `close()` for any cleanup (API connections, temporary
   files, etc.).

5. Register the new source type in
   `kerbside/sources/__init__.py:driver_class()`, importing the driver
   inside the branch so that importing the package stays cheap. The
   scrape loop and both console ticket minting paths look drivers up
   there.

   If the platform issues a SPICE ticket per console session (as oVirt
   and Proxmox VE do) rather than a fixed password, set
   `MINTS_TICKETS = True` and implement
   `mint_console_ticket(uuid, lifetime)`, returning a `MintedTicket`
   (with a `Tunnel` if the console is reached through an HTTP CONNECT
   proxy) or raising `ConsoleTicketUnavailable` (see `sources/base.py`).
   Kerbside then mints one when a session's first channel connects;
   `docs/proxy-architecture.md` describes the flow. Bound every request
   the driver makes with a timeout, and never log a ticket, a secret or
   a connect host.

6. Decide whether the platform's consoles can be downloaded as a direct
   `.vv` file. `BaseSource.DIRECT_CONSOLES` is true by default. Set it
   false if a ticket is too short-lived to carry in a file, or the
   console can only be reached through Kerbside: the direct `.vv`
   handler then answers 409 before it reads the source's secrets or
   mints, and the consoles page omits *Direct* for those consoles.

7. Add the client library, if the platform has one that the driver needs,
   to `pyproject.toml` as an optional dependency (commented out in main
   dependencies, listed in test dependencies if testable). A driver
   which uses `requests`, as `proxmox.py` does, needs none. Update the
   client libraries table in `docs/installation.md` either way.

8. Teach the Ansible role about the type, or a deployment which uses it is
   refused:
   - add it to `TYPE_REQUIRED`, with its required fields, in
     `ansible/roles/kerbside/files/kerbside-check-sources.py`, and to
     the list of types in that file's header;
   - describe it in `ansible/roles/kerbside/meta/argument_specs.yml`;
   - add its fields and an example to `ansible/README.md`;
   - update the unknown-type message that `tools/ci-test-ansible-role.sh`
     asserts (it lists the types in alphabetical order);
   - add cases to `kerbside/tests/unit/test_ansible_role.py`.

9. Add tests. Unit tests mock the platform's API at the driver's
   boundary (`kerbside/tests/unit/`); functional tests go in
   `kerbside/tests/functional/` following the pattern of
   `test_openstack.py` or `test_shakenfist.py`.

10. Document the new source type in `docs/console-sources.md`, including
    its `sources.yaml` fields, the privileges its account needs, the
    ports Kerbside must reach, and whether direct consoles are offered.
    Add the type to the lists of source types in `docs/schema.md`,
    `docs/installation.md`, `docs/network-ports.md` and the README's
    Console Sources link.

11. Update `ARCHITECTURE.md` to include the new source in the Source
    Abstraction table.

12. Run `tox -e py3` and `tox -e flake8` to verify.
