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
