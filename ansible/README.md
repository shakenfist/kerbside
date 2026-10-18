# shakenfist.kerbside

An Ansible collection for deploying
[Kerbside](https://github.com/shakenfist/kerbside), a SPICE VDI protocol
proxy for Shaken Fist, OpenStack, oVirt and static consoles, onto hosts you
choose. It carries one role, `shakenfist.kerbside.kerbside`, which installs
Kerbside into a virtualenv, writes its configuration and systemd units, runs
its database migrations and waits for it to be ready.

The role works with any console source type. It knows nothing about your
inventory: you map your hosts onto `kerbside_hosts` and your consoles onto
`kerbside_sources`. A collection release deploys the Kerbside release of the
same version by default, so collection 0.8.0 installs Kerbside 0.8.0. An
install from a git checkout reports `unreleased` as its
`kerbside_collection_version` and floors Kerbside at 0.7.0.

## Installing

```
ansible-galaxy collection install shakenfist.kerbside
```

or pin it in a `requirements.yml`:

```yaml
collections:
  - name: shakenfist.kerbside
    version: ">=0.8.0,<0.9.0"
```

It needs ansible-core 2.15 or later. The Kerbside hosts must run a Debian
family distribution with systemd and Python 3, and you provide a MySQL or
MariaDB database for Kerbside: create a `kerbside` database and a user with
all privileges on it. Kerbside does not support sqlite.

## Entry points

The role has five entry points, selected with `tasks_from`. Each is a plain
role invocation, and each documents its variables in
`roles/kerbside/meta/argument_specs.yml`, which ansible checks at run time.

| Entry point | Run on | What it does |
|-------------|--------|--------------|
| `validate` | Every Kerbside host, first | Refuses a configuration which cannot work, before any host is changed. Changes nothing, and does nothing when `kerbside_hosts` is empty. |
| `bootstrap` | Each Kerbside host | Installs build dependencies, the `kerbside` user, the virtualenv and the packages; records a hash of what was installed. |
| `config` | Each Kerbside host, after the proxy certificate is in place | Writes `kerbside.ini`, `sources.yaml` and the systemd units, each checked before it replaces the running file. Starts nothing. |
| `register` | Every Kerbside host together | Runs the database migration once, enables the services, restarts them only when the code, configuration, units or certificate changed, and waits for readiness. |
| `main` | Each Kerbside host | `bootstrap`, `config`, then `register`. Not `validate`. |

A minimal playbook:

```yaml
- hosts: kerbside
  tasks:
    - name: Validate
      ansible.builtin.include_role:
        name: shakenfist.kerbside.kerbside
        tasks_from: validate
      vars:
        kerbside_hosts: "{{ groups['kerbside'] }}"

- hosts: kerbside
  tasks:
    - name: Deploy Kerbside
      ansible.builtin.include_role:
        name: shakenfist.kerbside.kerbside
      vars:
        kerbside_hosts: "{{ groups['kerbside'] }}"
```

Validate every host before changing any: run it as its own play, as above.
Install the proxy certificate, key and CA into `kerbside_pki_dir` (or point
the override paths at your own) between `bootstrap` and `config` if you split
`main` up, or before `main` when you do not.

## Variables

Nothing is deployed unless `kerbside_hosts` is non-empty. Secrets are marked
`no_log` in the argument specs and are never printed.

### Required to deploy

| Variable | Default | Purpose |
|----------|---------|---------|
| `kerbside_hosts` | `[]` | The hosts this run validates or deploys to, in inventory order. Run-once work (the migration and the readiness check) happens on the first. List only hosts this run deploys to (see [Redeploys](#redeploys)). |
| `kerbside_public_fqdn` | `""` | The name SPICE clients use to reach the proxy. Also what a proxy certificate should be issued for. |
| `kerbside_sql_url` | `""` | The SQLAlchemy URL of Kerbside's database, for example `mysql://kerbside:PASSWORD@db.example.com/kerbside`. A secret. |
| `kerbside_auth_secret_seed` | `""` | Seeds Kerbside's API token signing. A secret of at least 32 characters, and never Kerbside's placeholder `~~unconfigured~~`. |
| `kerbside_sources` | `[]` | Kerbside's console sources. A secret. See below. |
| `kerbside_url` | `""` | Kerbside's base URL, rendered as the console token audience. Required when a source is of type `shakenfist`, where it must equal the cluster's `KERBSIDE_URL` byte for byte. Otherwise optional. |

### Console sources

`kerbside_sources` is written to `sources.yaml` as given, in the form
Kerbside's [console sources documentation](https://github.com/shakenfist/kerbside/blob/develop/docs/console-sources.md)
describes. Each source has a unique `source` name and a `type` of
`shakenfist`, `ovirt`, `openstack` or `static`, and each type has its own
required fields. `validate` checks them on the control node, by position and
key and never by value, and `config` checks the rendered file again before it
replaces the running one.

A Shaken Fist cluster. The username must be `system`, and the password is the
cluster's `kerbside` key:

```yaml
kerbside_sources:
  - source: cluster-a
    type: shakenfist
    url: https://sf.example.com:13000
    username: system
    password: "{{ vault_kerbside_key }}"
    ca_cert: "{{ lookup('file', 'sf-ca.pem') }}"
```

A static source, which needs no control plane:

```yaml
kerbside_sources:
  - source: lab
    type: static
    consoles:
      - uuid: 5d1d0d46-6b1f-4e4a-9a45-7b3e0d3c2f10
        name: lab-vm-1
        hypervisor: lab-hv-1
        hypervisor_ip: 192.0.2.10
        insecure_port: 5901
        ticket: "{{ vault_lab_vm_1_ticket }}"
```

For every source of type `shakenfist`, `bootstrap` installs
`kerbside_client_package`, `validate` requires `kerbside_url`, and `register`
waits for Kerbside to fetch that cluster's console token signing keys. For the
Shaken Fist side of that (the cluster's `KERBSIDE_URL`, the `kerbside` key and
the signing key), see the
[Shaken Fist operator guide](https://github.com/shakenfist/shakenfist/blob/develop/docs/operator_guide/installation.md).

### Packages

| Variable | Default | Purpose |
|----------|---------|---------|
| `kerbside_package` | `kerbside>=0.7.0` in a checkout, `kerbside==<version>` in a release | What is installed into the virtualenv: a requirement or a wheel path. The floor is the first release which stopped returning source passwords from its API. |
| `kerbside_proxy_package` | `""` | The `kerbside-proxy` package. Empty installs whichever version `kerbside_package` requires, which a Kerbside release pins exactly. |
| `kerbside_client_package` | `shakenfist-client` | The Shaken Fist client Kerbside's Shaken Fist source driver imports. Installed only when a source is of type `shakenfist`. |
| `kerbside_local_wheels` | `[]` | Wheels on the control node to install in place of the package specs. See below. |
| `kerbside_pip_extra` | `""` | Extra arguments for both pip (installing uv) and `uv pip install`, for example `--index-url`; use flags both accept. |
| `kerbside_collection_version` | `unreleased` in a checkout | Read-only: the release this collection was built as. Not a setting. |

**Local wheels.** A `kerbside-*.whl` replaces `kerbside_package` and a
`kerbside_proxy-*.whl` replaces `kerbside_proxy_package`. `validate` refuses
any other file name, two wheels for one package and a path which is not a
file. `bootstrap` copies each to `kerbside_state_dir/wheels` on the host under
its own file name, so the same wheel gives the same code hash and does not
restart Kerbside on a redeploy, while a wheel whose bytes differ does. A
Kerbside wheel must be built from a git checkout, not an unpacked sdist, or it
is missing `kerbside.sources` and `kerbside.migrations`
([kerbside#326](https://github.com/shakenfist/kerbside/issues/326)).

### Ports

| Variable | Default | Purpose |
|----------|---------|---------|
| `kerbside_api_address` | `0.0.0.0` | The address the API (gunicorn) binds. An IPv6 address may be given bare. |
| `kerbside_api_port` | `13002` | The API port. |
| `kerbside_api_workers` | `2` | The number of gunicorn workers. |
| `kerbside_vdi_secure_port` | `5900` | The TLS SPICE port. |
| `kerbside_vdi_insecure_port` | `5901` | The plaintext SPICE port. |
| `kerbside_metrics_port` | `13003` | The Prometheus metrics port. |
| `kerbside_reserved_ports` | `[]` | Ports something else on the host uses. |

The four Kerbside ports must be distinct, and none may be in
`kerbside_reserved_ports`. Each entry there is a port or a `[low, high]` range
including both ends, between 1 and 65535. The default reserves nothing: a
deployment which shares its hosts passes what those hosts' other services
listen on. On a Shaken Fist hypervisor that is the daemons' ports (13000,
13001, 13005, 13006 and 13007) and the instance console range from 30000:

```yaml
kerbside_reserved_ports:
  - 13000
  - 13001
  - [13005, 13007]
  - [30000, 65535]
```

### Certificates

By default the proxy certificate, key and CA are read from `kerbside_pki_dir`,
where your playbook installs them before `config` runs, for example with
Shaken Fist's `internal_ca` role. To use your own instead, set all three of
`kerbside_proxy_cert_path`, `kerbside_proxy_key_path` and
`kerbside_cacert_path` to paths on the Kerbside host. All or none: `validate`
refuses anything in between.

| Variable | Default | Purpose |
|----------|---------|---------|
| `kerbside_proxy_cert_path` | `""` | Operator-supplied proxy certificate. |
| `kerbside_proxy_key_path` | `""` | Its private key. |
| `kerbside_cacert_path` | `""` | The CA which signed it, embedded in the console files handed to clients. |
| `kerbside_pki_dir` | `/etc/kerbside/pki` | Where the three are read from when no override is set. |
| `kerbside_proxy_cert_name` | `server-cert.pem` | The certificate's file name in `kerbside_pki_dir`. |
| `kerbside_proxy_key_name` | `server-key.pem` | The key's file name. |
| `kerbside_proxy_cacert_name` | `ca-cert.pem` | The CA's file name. |

### Readiness

| Variable | Default | Purpose |
|----------|---------|---------|
| `kerbside_ready_retries` | `60` | How many times, three seconds apart, `register` checks that Kerbside fetched each Shaken Fist source's signing keys during this deploy. The default allows three of Kerbside's 60 second scrape passes. Unused without a Shaken Fist source. |

### Layout and ownership

These rarely change. Most exist only so a test without root can redirect them.

| Variable | Default | Purpose |
|----------|---------|---------|
| `kerbside_config_dir` | `/etc/kerbside` | Where configuration is written. Kerbside reads `/etc/kerbside/kerbside.ini` and nowhere else, so keep the default in production. |
| `kerbside_state_dir` | `/srv/kerbside` | The `kerbside` user's home, and where the role records what it deployed. |
| `kerbside_venv` | `/srv/kerbside/venv` | The virtualenv Kerbside is installed into. |
| `kerbside_unit_dir` | `/etc/systemd/system` | Where the systemd units are written. |
| `kerbside_user` | `kerbside` | The system user Kerbside runs as. |
| `kerbside_group` | `kerbside` | Its group. |
| `kerbside_file_owner` | `root` | Owner of files Kerbside must not change. |
| `kerbside_file_group` | `root` | Group of files Kerbside need not read. |

## Redeploys

A redeploy restarts Kerbside only when its code (including the version of any
package in its virtualenv other than pip and uv), configuration, systemd units
or certificate changed. Each deploy waits for the readiness described above.

Every host which needs a restart restarts in the same task, so a redeploy
which changes Kerbside drops every console session at once, on every host.
For a rolling restart, run the play with `serial`.

The database migration and the readiness check run once, on the first host in
`kerbside_hosts`. With `--limit` or `serial`, `kerbside_hosts` must list only
the hosts this run deploys to. A first host which is left out of the run would
migrate from its old virtualenv, and the hosts which are deployed would restart
on new code against the old schema. The run-once tasks also take
`kerbside_venv`, `kerbside_user` and the other paths from the play's first
host, so keep those the same on every Kerbside host.

## Links

* [Kerbside](https://github.com/shakenfist/kerbside) and its
  [documentation](https://github.com/shakenfist/kerbside/blob/develop/docs/index.md)
* [Issues](https://github.com/shakenfist/kerbside/issues)
* [Shaken Fist operator guide](https://github.com/shakenfist/shakenfist/blob/develop/docs/operator_guide/installation.md)
