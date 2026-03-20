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

Ryll, located in the `testclient/` directory, is a simple python native SPICE
client used to implement various load tests. It has its own README file in that
subdirectory.

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

## Build the load testing OCI container images

There are a series of OCI container images intended for load testing. These need
to be build from this top level directory however because of the way
`docker build` likes to constrain what files you can copy into a container image.

### Latency load test

This is the first load test that was implemented. It uses a UEFI binary as a
test target, and sends keystrokes every two seconds to the instance running that
binary. It then measures how long it takes to receive a display update back.

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
