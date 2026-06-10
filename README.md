# Kerbside, a SPICE VDI proxy

Kerbside is a SPICE VDI protocol proxy written in python. The long term idea is
that this would sit out the front of your Shaken Fist cluster and provide VDI
access to VMs running inside the cluster. It does this by determining what
VM to proxy your traffic to based on the password you provide
when connecting.

Kerbside currently knows how to proxy console sessions for Shaken Fist,
OpenStack, and oVirt. Ironically, OpenStack is probably the best documented of
those at the moment because there are patches to add deployment support for
Kerbside to Kolla-Ansible, whereas there is no deployment support for Shaken
Fist just yet.

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) - High-level system architecture
- [AGENTS.md](AGENTS.md) - AI agent guidelines for working on this codebase
- [docs/](docs/) - Full documentation:
  - [Documentation Index](docs/index.md) - Full documentation index with
    overview and introduction
  - Operator documentation:
    - [Configuration](docs/configuration.md) - Configuration reference
    - [Console Sources](docs/console-sources.md) - Configuring sources.yaml
  - Protocol documentation:
    - [Protocol Overview](docs/protocol-overview.md) - SPICE protocol
      fundamentals
    - [Link Protocol](docs/spice-link-protocol.md) - Connection handshake and
      authentication
    - [Channel Protocols](docs/channel-protocols.md) - Per-channel message
      formats (main, display, inputs, cursor, audio, smartcard)
    - [Keyboard Scancodes](docs/scancodes.md) - IBM PC XT scancode reference
      for the inputs channel
    - [Compression Protocols](docs/compression-protocols.md) - LZ and GLZ
      image compression formats
    - [Capabilities](docs/capabilities.md) - Channel capability negotiation
    - [USB Redirection](docs/usb-redirection.md) - USB device redirection
      protocol
    - [VD Agent Protocol](docs/vd-agent-protocol.md) - Guest agent for
      clipboard, file transfer, and display configuration
    - [Proxy Architecture](docs/proxy-architecture.md) - Internal proxy design

## Bootstrap CSS

Kerbside uses bootstrap CSS for styling. This was constructed by downloading
Bootstrap 5.3 and jQuery 3.7.0 and then installing to `kerbside/api/static/js`.

## Axios

Kerbside's web administration API uses Axios for HTTP requests. Version 1.6.5
is cached at `kerbside/api/static/js`.

## Ryll

Ryll is the upstream Rust SPICE client at
[shakenfist/ryll](https://github.com/shakenfist/ryll). The latency loadtest
image builds the Ryll binary from source (stage 1 of
`loadtests/latency/Dockerfile`) and ships it in the runtime stage. A Python
orchestrator at `loadtests/latency/orchestrator.py` drives Ryll's control
socket and writes a CSV of latency samples.

The latency metric currently measured is SPICE PING/PONG round-trip time (the
v1 control-socket `latency` event). This is a temporary regression from the
legacy keypress-to-screen measurement — phase 6 of the test-harness plan will
restore the original metric via a `surface_drawn` event in the control socket.
The CSV shape is unchanged from the legacy loadtest: one float per line,
seconds, no header. See
`docs/plans/PLAN-test-harness-phase-04-port-latency.md` for the full
rationale.

## Creating an oVirt SPICE Test Target

The `tools/start-test-target.py` script creates an oVirt VM suitable as a
SPICE test target. It uploads a desktop QCOW2 disk image (with
qemu-guest-agent and spice-vdagent pre-installed), creates a template from
it, then creates and starts a VM with SPICE display enabled. When
`--host-address` is provided, it also sets up the full oVirt infrastructure
(datacenter, cluster, hypervisor host, and local storage domain).

```bash
python tools/start-test-target.py \
    --url https://ovirt-engine.example/ovirt-engine/api \
    --password secret \
    --ca-file /path/to/ca.pem \
    --datacenter mydc \
    --cluster mycluster \
    --storage-domain mystorage \
    --disk-image /path/to/desktop.qcow2
```

Run with `--help` for all options (disk image path, template name, VM name,
memory size, host setup, timeout, debug logging).

Supporting shell scripts in `tools/` handle oVirt host preparation in CI:
- `ovirt-install-base.sh` — base package installation (EPEL, utilities)
- `ovirt-patch-ovn.sh` — patches oVirt 4.5 OVN Ansible role bug (#949)
- `ovirt-prepare-host.sh` — engine health check, SSH setup, KVM verification
- `ovirt-gather-artifacts.sh` — collects RPM lists and logs for CI artifacts

## Tempest Tests Against a Kolla-Ansible Deployment

The `tempest-plugin/` directory is a separate releasable that contributes
Kerbside-specific Tempest tests; see `tempest-plugin/README.md` for what it
covers.

`tools/run-tempest-tests` drives a curated subset of those tests against a
running Kolla-Ansible deployment. It is invoked automatically by the
`openstack_matrix` job in `.github/workflows/functional-tests.yml` after the
`test-console` smoke check, so the GitHub Actions CI iterates on the
plugin's tests on every PR rather than relying on upstream Zuul as the
first signal. The script:

1. Creates a Python venv at `/srv/kerbside-tempest/venv`.
2. Pip-installs `tempest`, `python-tempestconf`, and the local
   `tempest-plugin/` checkout into it.
3. Runs `tempest init` plus `discover-tempest-config` against
   `/etc/kolla/clouds.yaml`'s `kolla-admin` cloud with
   `compute-feature-enabled.spice_console True`.
4. Injects the `[kerbside]` group pointing at the Kolla CA bundle.
5. Runs `tempest run` against a regex that selects the kerbside plugin
   tests. The upstream `tempest.api.compute.admin.test_spice` (spice-direct)
   test deliberately bypasses Kerbside by connecting straight to the
   libvirt SPICE port, so it is not in the default regex — pass
   `--regex` to opt back in if you want it.

Run it manually on a deployed all-in-one node with
`sudo bash tools/run-tempest-tests`; pass `--help` to see knobs (regex,
workspace location, CA bundle path, etc.).

## Build the load testing OCI container images

There are a series of OCI container images intended for load testing. These need
to be build from this top level directory however because of the way
`docker build` likes to constrain what files you can copy into a container image.

### Latency load test

This is the first load test that was implemented. It uses a UEFI binary as a
test target and drives Ryll (the upstream Rust SPICE client) in headless mode
against an OpenStack-provisioned instance. A Python orchestrator at
`loadtests/latency/orchestrator.py` connects to Ryll via its control socket,
sends spacebar keypresses every two seconds, collects SPICE PING/PONG
round-trip latency samples, and writes them to a CSV (one float per line,
seconds). See the `Ryll` section above for a note on the metric definition.

To build this OCI image, do this:

```
docker build . -f loadtests/latency/Dockerfile -t kerbside-latency:latest
```

For your convenience, there is also a version of this image at
https://images.shakenfist.com/testimages/kerbside-latency.tar.gz

## Database Migrations

Kerbside uses Alembic for database schema migrations. The migration files are
located in the `alembic/versions/` directory.

### Creating a New Migration

To create a new migration:

```bash
cd /path/to/shakenfist/kerbside
alembic revision -m "description_of_your_changes"
```

This will create a new migration file in `alembic/versions/`. Edit the generated
file to add your schema changes in the `upgrade()` and `downgrade()` functions.

Example:

```python
def upgrade() -> None:
    op.add_column('table_name', sa.Column('column_name', sa.Type()))

def downgrade() -> None:
    op.drop_column('table_name', 'column_name')
```

### Applying Migrations

To apply all pending migrations:

```bash
alembic upgrade head
```

To rollback one migration:

```bash
alembic downgrade -1
```

**Note:** Alembic automatically uses the database URL from the kerbside
configuration, so ensure your kerbside config is properly set up before running
migrations.

## Checking OS Package Dependencies

Kerbside requires certain OS-level packages to be installed. You can check for
missing dependencies using bindep via tox.

### Check for Missing OS Packages

To check which OS packages are required but not installed:

```bash
tox -e bindep
```

This will read the `bindep.txt` file and report any missing system packages
that need to be installed for your platform. The bindep tool automatically
detects your operating system and checks for platform-specific packages.

### Installing Missing Packages

After running the bindep check, install any missing packages using your system's
package manager:

**Debian/Ubuntu:**
```bash
sudo apt-get install <package-names>
```

**RHEL/CentOS/Fedora:**
```bash
sudo dnf install <package-names>
```

The `bindep.txt` file includes dependencies for MariaDB/MySQL client libraries,
XML parsing libraries, and build tools needed for compiling Python extensions.
