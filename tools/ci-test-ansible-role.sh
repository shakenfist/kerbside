#!/bin/bash
#
# ci-test-ansible-role.sh -- drive the shakenfist.kerbside collection's
# kerbside role through its validate, bootstrap, config and register entry
# points against localhost, and check what they do.
#
# It proves that validate refuses each configuration the role cannot
# deploy, each with its own message, and passes a correct one and an empty
# kerbside_hosts; that kerbside_sources is checked by Kerbside's rules for
# each source type, by position and key and never by value; that a Kerbside
# port in kerbside_reserved_ports is refused, as a single port or in a range;
# that bootstrap's code hash follows every package version in the virtualenv
# and the installed files, but not pip's, uv's, __pycache__ or the freeze
# order, and installs and hashes the Shaken Fist client only for a Shaken
# Fist source; that local wheels are copied, installed in place of the
# package they are named for, and give the same hash for the same bytes;
# that config renders a kerbside.ini which configparser reads back, as
# Kerbside does with interpolation off, to exactly the values given (a % in
# kerbside_sql_url included, never doubled), whose token audience is
# kerbside_url byte for byte, and a sources.yaml which loads back as
# kerbside_sources exactly; that a Shaken Fist deployment renders both files
# as the role did before it took any source; that a render either checker
# refuses leaves the running file in place and nothing behind; that the
# desired-state hash is stable across reruns, follows every file Kerbside
# runs with, and returns to its first value when they are restored; that
# register waits on exactly the Shaken Fist sources, and on none without
# one; and that no source's password, no console ticket, nor any other
# secret reaches the ansible output.
#
# register runs without its migration and its units, which need MariaDB and
# systemd, and with a stub runuser which records how the readiness check
# was asked and answers it. bootstrap runs against a stub virtualenv whose
# pip and uv install nothing from PyPI, since a real install needs it, and
# with the apt, user and group tasks skipped by tag; the other cases are
# given kerbside_code_hash, which it sets, as an extra var instead.
#
# It runs without root. The role's paths and owners are variables with the
# production defaults, so they point into a temporary directory, which is
# removed on exit, and at the invoking user. The virtualenv's Python, which
# config runs its helper scripts with, is a wrapper around this test's
# python3, which has cryptography and PyYAML (ansible-core depends on both).
# Secrets are passed with -e @file, never -e key=value: ansible echoes
# command line extra vars at -v and above. The working tree is used in place
# via a symlinked collections path, so this tests the role as checked out.
#
# Run from anywhere, with ansible-playbook, openssl and python3 on PATH:
#
#     tools/ci-test-ansible-role.sh
#
# Set KEEP_WORK=1 to keep the temporary directory, and every run's log in
# it, for debugging.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COLLECTION_DIR="${REPO_ROOT}/ansible"

CURRENT_CASE='setup'
LAST_LOG=''

WORK="$(mktemp -d "${TMPDIR:-/tmp}/ci-test-ansible-role.XXXXXX")"
trap '[ -n "${KEEP_WORK:-}" ] || rm -rf "${WORK}"' EXIT

fail() {
    echo "FAIL [${CURRENT_CASE}]: $*" >&2
    if [ -n "${LAST_LOG}" ] && [ -f "${LAST_LOG}" ]; then
        echo "---- last 40 lines of ${LAST_LOG##*/} ----" >&2
        tail -n 40 "${LAST_LOG}" >&2
    fi
    exit 1
}

need() {
    command -v "$1" > /dev/null || fail "$1 not found on PATH: $2"
}

need ansible-playbook 'install ansible-core (the sanity job gets it with ansible-lint)'
need openssl 'install the openssl package'
need python3 'install python3'

# The interpreter itself, not a pyenv shim or a symlink into a virtualenv:
# the wrapper below must reach the same site-packages.
PY="$(python3 -c 'import sys; print(sys.executable)')"
"${PY}" -c 'import cryptography, yaml' 2> /dev/null \
    || fail "${PY} cannot import cryptography and yaml, which config's helper scripts need"

mkdir -p "${WORK}/collections/ansible_collections/shakenfist" "${WORK}/logs" \
    "${WORK}/ansible-tmp" "${WORK}/vars"
ln -s "${COLLECTION_DIR}" "${WORK}/collections/ansible_collections/shakenfist/kerbside"

# An empty config, so neither a developer's ~/.ansible.cfg nor an
# installed copy of the collection changes what runs.
: > "${WORK}/ansible.cfg"
export ANSIBLE_CONFIG="${WORK}/ansible.cfg"
export ANSIBLE_COLLECTIONS_PATH="${WORK}/collections"
export ANSIBLE_COLLECTIONS_SCAN_SYS_PATH=false
export ANSIBLE_LOCAL_TEMP="${WORK}/ansible-tmp"
export ANSIBLE_REMOTE_TMP="${WORK}/ansible-tmp"
export ANSIBLE_NOCOLOR=1
export ANSIBLE_STDOUT_CALLBACK=default

# The role's directories, as config would find them on a Kerbside host.
CONF="${WORK}/etc/kerbside"
PKI="${CONF}/pki"
STATE="${WORK}/srv/kerbside"
VENV="${WORK}/venv"
UNITS="${WORK}/units"
OVERRIDE="${WORK}/override"
mkdir -p "${PKI}" "${VENV}/bin" "${UNITS}" "${OVERRIDE}" "${WORK}/certs"

# The virtualenv's Python. A wrapper rather than a symlink: a symlink to a
# virtualenv's python, from outside it, loses that virtualenv's packages.
cat > "${VENV}/bin/python" << EOF
#!/bin/sh
exec '${PY}' "\$@"
EOF
chmod +x "${VENV}/bin/python"

# ca NAME SUBJECT: a self-signed CA, as ${WORK}/certs/NAME-{key,cert}.pem.
ca() {
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
        -keyout "${WORK}/certs/$1-key.pem" -out "${WORK}/certs/$1-cert.pem" \
        -days 30 -subj "$2" 2> /dev/null || fail "openssl could not make the CA $1"
}

# cert NAME SUBJECT CA_NAME [SERIAL]: a certificate for SUBJECT signed by
# CA_NAME, as ${WORK}/certs/NAME-{key,cert}.pem. The key is made once, so the
# same subject with another serial is a renewal.
cert() {
    local name="$1" subject="$2" ca_name="$3" serial="${4:-1}"
    if [ ! -f "${WORK}/certs/${name}-key.pem" ]; then
        openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 \
            -out "${WORK}/certs/${name}-key.pem" 2> /dev/null \
            || fail "openssl could not make the key for ${name}"
    fi
    openssl req -new -key "${WORK}/certs/${name}-key.pem" -subj "${subject}" \
        -out "${WORK}/certs/${name}.csr" 2> /dev/null \
        || fail "openssl could not make the request for ${name}"
    openssl x509 -req -in "${WORK}/certs/${name}.csr" \
        -CA "${WORK}/certs/${ca_name}-cert.pem" -CAkey "${WORK}/certs/${ca_name}-key.pem" \
        -set_serial "${serial}" -days 30 -out "${WORK}/certs/${name}-cert.pem" 2> /dev/null \
        || fail "openssl could not sign the certificate for ${name}"
}

# The proxy CA and certificate, installed under kerbside_pki_dir by the
# default names, and a second pair for the operator override paths, with a
# subject of its own so a render can be told apart. The CAs a Shaken Fist
# cluster and an oVirt engine serve are a third and a fourth.
ca proxy-ca '/O=Kerbside Test/CN=Kerbside Test Proxy CA'
cert proxy '/O=Kerbside Test/CN=console.example.com' proxy-ca
cp "${WORK}/certs/proxy-cert.pem" "${PKI}/server-cert.pem"
cp "${WORK}/certs/proxy-cert.pem" "${WORK}/certs/proxy-cert-first.pem"
cp "${WORK}/certs/proxy-key.pem" "${PKI}/server-key.pem"
cp "${WORK}/certs/proxy-ca-cert.pem" "${PKI}/ca-cert.pem"
ca override-ca '/O=Operator/CN=Operator Proxy CA'
cert override '/C=AU/O=Operator, Inc./CN=vdi.example.org' override-ca
cp "${WORK}/certs/override-cert.pem" "${OVERRIDE}/cert.pem"
cp "${WORK}/certs/override-key.pem" "${OVERRIDE}/key.pem"
cp "${WORK}/certs/override-ca-cert.pem" "${OVERRIDE}/ca.pem"
ca sf-ca '/O=Shaken Fist/CN=Shaken Fist Test SPICE CA'
ca ovirt-ca '/O=oVirt/CN=oVirt Test Engine CA'

URL='https://console.example.com:13002/kerbside/'
FQDN='console.example.com'
# The secrets: one password for each source type which has one, a static
# console's ticket, the seed and the SQL URL's password. The seed is exactly
# 32 characters, validate's minimum. The SQL URL's password carries a %,
# which the INI must double; its distinctive part is what the output is
# searched for, so that a doubled copy is found too.
SYSTEM_KEY='kb-system-key-Vt7qL2mXc9Rw'
SF2_KEY='kb-second-cluster-Hp3sW8dQ'
OVIRT_PASSWORD='ovirt-pw-Zr6kN1vB4tYe'
OPENSTACK_PASSWORD='openstack-pw-Ld9xF2cM7qUa'
STATIC_TICKET='spice-ticket-Gw5jR8nT3hKo'
SEED='seed-Jk4pW8zN2bQ6vT1yH5cR9mD3fL7'
SQL_SECRET='Xq8Tz3LmPw'
SQL_URL="mysql+pymysql://kerbside:pw%25${SQL_SECRET}@db.example.com/kerbside"
[ "${#SEED}" -eq 32 ] || fail "the test seed is ${#SEED} characters, not 32"
SECRETS=("${SYSTEM_KEY}" "${SF2_KEY}" "${OVIRT_PASSWORD}" "${OPENSTACK_PASSWORD}"
    "${STATIC_TICKET}" "${SEED}" "${SEED:0:31}" "${SQL_SECRET}")

SF_CA_FILE="${WORK}/certs/sf-ca-cert.pem"

# A CA as a Shaken Fist cluster serves it, fixed rather than generated so
# that the Shaken Fist deployment case can compare a render with the text the
# role produced before it took any source. It is never parsed as a
# certificate.
FIXED_CA='-----BEGIN CERTIFICATE-----
MIIBszCCAVmgAwIBAgIUS2VyYnNpZGUgZXF1aXZhbGVuY2UgdGVzdCBDQTAKBggq
hkjOPQQDAjAvMRQwEgYDVQQKDAtTaGFrZW4gRmlzdDEXMBUGA1UEAwwORXF1aXZh
-----END CERTIFICATE-----
'

# The vars files every case builds on, written by python since the CAs are
# multi-line and it reads every value from its environment:
#
#   * common.json, given to every run: a valid configuration, as a Kerbside
#     host co-located with a Shaken Fist node sees it, with one Shaken Fist
#     source, using the loopback API, and Shaken Fist's reserved ports.
#   * multi.json: one source of every type, and a second Shaken Fist source,
#     each carrying a secret.
#   * no-sf.json: an oVirt and a static source, and no kerbside_url.
#   * shakenfist.json: Shaken Fist's deployment with the fixed CA.
URL="${URL}" FQDN="${FQDN}" SYSTEM_KEY="${SYSTEM_KEY}" SF2_KEY="${SF2_KEY}" \
    OVIRT_PASSWORD="${OVIRT_PASSWORD}" OPENSTACK_PASSWORD="${OPENSTACK_PASSWORD}" \
    STATIC_TICKET="${STATIC_TICKET}" SEED="${SEED}" SQL_URL="${SQL_URL}" \
    SF_CA_FILE="${SF_CA_FILE}" OVIRT_CA_FILE="${WORK}/certs/ovirt-ca-cert.pem" \
    FIXED_CA="${FIXED_CA}" CONF="${CONF}" STATE="${STATE}" VENV="${VENV}" \
    UNITS="${UNITS}" USER_NAME="$(id -un)" GROUP_NAME="$(id -gn)" \
    "${PY}" - "${WORK}" << 'PYEOF'
import json
import os
import sys

env = os.environ
work = sys.argv[1]
with open(env['SF_CA_FILE']) as f:
    sf_ca = f.read()
with open(env['OVIRT_CA_FILE']) as f:
    ovirt_ca = f.read()


def sf_source(name, url, password, ca):
    return {'source': name, 'type': 'shakenfist', 'url': url,
            'username': 'system', 'password': password, 'ca_cert': ca}


# Shaken Fist's listener ports and its instance console range.
sf_reserved = [13000, 13001, 13005, 13006, 13007, [30000, 65535]]
ovirt = {
    'source': 'engine', 'type': 'ovirt',
    'url': 'https://engine.example.com/ovirt-engine',
    'username': 'admin@ovirt@internalsso',
    'password': env['OVIRT_PASSWORD'], 'ca_cert': ovirt_ca,
}
openstack = {
    'source': 'kolla', 'type': 'openstack',
    'url': 'http://keystone.example.com:5000', 'username': 'kerbside',
    'password': env['OPENSTACK_PASSWORD'], 'project_name': 'service',
    'user_domain_id': 'default', 'project_domain_id': 'default',
}
static = {
    'source': 'lab', 'type': 'static',
    'consoles': [{
        'uuid': '6f4e2c1a-0000-0000-0000-000000000001', 'name': 'lab-vm',
        'hypervisor': 'localhost', 'hypervisor_ip': '127.0.0.1',
        'insecure_port': 5910, 'secure_port': None,
        'ticket': env['STATIC_TICKET'],
    }],
}

files = {
    'common.json': {
        'kerbside_url': env['URL'],
        'kerbside_public_fqdn': env['FQDN'],
        'kerbside_auth_secret_seed': env['SEED'],
        'kerbside_sql_url': env['SQL_URL'],
        'kerbside_sources': [sf_source(
            'sf', 'http://localhost:13000', env['SYSTEM_KEY'], sf_ca)],
        'kerbside_reserved_ports': sf_reserved,
        'kerbside_hosts': ['localhost'],
        'kerbside_code_hash': 'code-hash-1',
        'kerbside_config_dir': env['CONF'],
        'kerbside_state_dir': env['STATE'],
        'kerbside_venv': env['VENV'],
        'kerbside_unit_dir': env['UNITS'],
        'kerbside_user': env['USER_NAME'],
        'kerbside_group': env['GROUP_NAME'],
        'kerbside_file_owner': env['USER_NAME'],
        'kerbside_file_group': env['GROUP_NAME'],
    },
    'multi.json': {
        'kerbside_sources': [
            sf_source('sf', 'http://localhost:13000', env['SYSTEM_KEY'],
                      sf_ca),
            ovirt, openstack, static,
            sf_source('sf2', 'https://sf2.example.com:13000',
                      env['SF2_KEY'], sf_ca),
        ],
    },
    'no-sf.json': {
        'kerbside_url': '',
        'kerbside_sources': [ovirt, static],
    },
    'shakenfist.json': {
        'kerbside_sources': [sf_source(
            'sf', 'http://localhost:13000', env['SYSTEM_KEY'],
            env['FIXED_CA'])],
        'kerbside_reserved_ports': sf_reserved,
    },
}
for name, content in files.items():
    path = os.path.join(work, 'common.json' if name == 'common.json'
                        else os.path.join('vars', name))
    with open(path, 'w') as f:
        json.dump(content, f, indent=2)
PYEOF
MULTI_VARS="${WORK}/vars/multi.json"
NO_SF_VARS="${WORK}/vars/no-sf.json"
SF_VARS="${WORK}/vars/shakenfist.json"

# role_playbook NAME ENTRY_POINT [REPORT...]: a playbook which runs one of
# the role's entry points, and then reports each REPORT, a debug message, on
# a line of its own for the script to read.
role_playbook() {
    local name="$1" entry="$2"
    shift 2
    {
        printf -- "---\n- name: Run the kerbside role's %s entry point\n" "${entry}"
        printf '  hosts: localhost\n  connection: local\n  gather_facts: false\n'
        printf '  tasks:\n    - name: Run %s\n' "${entry}"
        printf '      ansible.builtin.include_role:\n'
        printf '        name: shakenfist.kerbside.kerbside\n'
        printf '        tasks_from: %s\n' "${entry}"
        local report
        for report in "$@"; do
            printf '\n    - name: Report\n      ansible.builtin.debug:\n'
            printf '        msg: "%s"\n' "${report}"
        done
    } > "${WORK}/${name}.yml"
}

role_playbook validate validate
# config, then the desired state it computed and the files that went into
# it.
role_playbook config config \
    'DESIRED_STATE={{ kerbside_desired_state }}' \
    "DESIRED_FILES={{ kerbside_config_stats.results | map(attribute='item') | join('|') }}"
role_playbook bootstrap bootstrap 'CODE_HASH={{ kerbside_code_hash }}'
role_playbook register register

# write_vars NAME JSON: an extra vars file for one run.
write_vars() {
    echo "$2" > "${WORK}/vars/$1.json"
    echo "${WORK}/vars/$1.json"
}

RUNS=0
# run_ansible PLAYBOOK [extra vars file...]: run a playbook against localhost
# into a fresh log, at ${VERBOSITY} if that is set, leaving the PLAY RECAP's
# changed= and skipped= counts in CHANGED and SKIPPED. Returns its status.
# COMMON_VARS replaces common.json as the first extra vars file.
run_ansible() {
    local playbook="$1"
    shift
    local args=(-e "@${COMMON_VARS:-${WORK}/common.json}")
    local f
    for f in "$@"; do
        args+=(-e "@${f}")
    done
    if [ -n "${VERBOSITY:-}" ]; then
        args+=("${VERBOSITY}")
    fi
    RUNS=$((RUNS + 1))
    LAST_LOG="${WORK}/logs/run-${RUNS}.log"
    local rc=0
    ansible-playbook -i localhost, -c local -e ansible_become=false \
        "${args[@]}" "${playbook}" < /dev/null > "${LAST_LOG}" 2>&1 || rc=$?
    CHANGED="$(sed -n 's/^localhost .* changed=\([0-9]*\) .*/\1/p' "${LAST_LOG}")"
    SKIPPED="$(sed -n 's/^localhost .* skipped=\([0-9]*\) .*/\1/p' "${LAST_LOG}")"
    return "${rc}"
}

# validate_passes / config_passes [extra vars file...]: expect success.
validate_passes() {
    run_ansible "${WORK}/validate.yml" "$@" || fail 'validate failed'
}

# config_passes also leaves the desired state in DESIRED, and the files
# hashed into it, |-separated, in DESIRED_FILES.
config_passes() {
    run_ansible "${WORK}/config.yml" "$@" || fail 'config failed'
    DESIRED="$(sed -n 's/.*"msg": "DESIRED_STATE=\([0-9a-f]\{64\}\)".*/\1/p' "${LAST_LOG}")"
    [ -n "${DESIRED}" ] || fail 'config did not report a desired state'
    DESIRED_FILES="$(sed -n 's/.*"msg": "DESIRED_FILES=\(.*\)".*/\1/p' "${LAST_LOG}")"
}

# validate_fails / config_fails PATTERN [extra vars file...]: expect a failure
# whose output matches the extended regex PATTERN.
validate_fails() {
    local pattern="$1"
    shift
    if run_ansible "${WORK}/validate.yml" "$@"; then
        fail "validate succeeded, expected a failure matching '${pattern}'"
    fi
    grep -qE -- "${pattern}" "${LAST_LOG}" || fail "the failure does not match '${pattern}'"
}

config_fails() {
    local pattern="$1"
    shift
    if run_ansible "${WORK}/config.yml" "$@"; then
        fail "config succeeded, expected a failure matching '${pattern}'"
    fi
    grep -qE -- "${pattern}" "${LAST_LOG}" || fail "the failure does not match '${pattern}'"
}

assert_output_has() {
    grep -qF -- "$1" "${LAST_LOG}" || fail "the ansible output lacks '$1'"
}

assert_output_lacks() {
    if grep -qF -- "$1" "${LAST_LOG}"; then
        fail "the ansible output contains '$1'"
    fi
}

# Every validate case's distinctive message names its refusal; a run which
# failed for some other reason too, or never reached the role, must not pass
# for it.
assert_validate_refused() {
    grep -q '^localhost .* failed=1 ' "${LAST_LOG}" || fail 'the run did not fail exactly one task'
    grep -qE '^(fatal: \[localhost\]: FAILED!|failed: \[localhost\] \(item=)' "${LAST_LOG}" \
        || fail 'no task failed on localhost'
}

# sources_refused NAME JSON_LIST MESSAGE...: validate must refuse the
# kerbside_sources JSON_LIST with every MESSAGE, each a whole line of the
# checker's, in the output.
sources_refused() {
    local name="$1" sources="$2"
    shift 2
    validate_fails 'kerbside_sources on localhost cannot be used by Kerbside' \
        "$(write_vars "sources-${name}" "{\"kerbside_sources\": ${sources}}")"
    assert_validate_refused
    local message
    for message in "$@"; do
        assert_output_has "sources.yaml refused: ${message}"
    done
}

case_1_feature_off() {
    CURRENT_CASE='case 1: validate passes an empty kerbside_hosts'
    # Everything else empty or wrong too: none of it applies without hosts.
    validate_passes "$(write_vars off '{
      "kerbside_hosts": [], "kerbside_url": "", "kerbside_sources": [],
      "kerbside_auth_secret_seed": "~~unconfigured~~",
      "kerbside_reserved_ports": [[5, 4]], "kerbside_api_port": 13000,
      "kerbside_proxy_cert_path": "/x", "kerbside_local_wheels": ["/nonexistent.whl"]
    }')"
    assert_output_has 'kerbside_hosts is empty, so Kerbside is not being deployed'
}

case_2_valid() {
    CURRENT_CASE='case 2: validate passes a valid configuration'
    # Shaken Fist's deployment, at -vvv for the secrets search. Only the
    # feature-off message is skipped, and the two loops over
    # kerbside_local_wheels, which is empty.
    VERBOSITY=-vvv validate_passes
    [ "${SKIPPED}" = 3 ] || fail "expected only the feature-off message and the wheel checks skipped, skipped=${SKIPPED}"
    assert_output_lacks 'kerbside_hosts is empty'

    # A dedicated host, which reserves nothing, so a port at 30000 or above is
    # legal; all three overrides.
    validate_passes "$(write_vars valid-dedicated "{
      \"kerbside_reserved_ports\": [],
      \"kerbside_metrics_port\": 40000,
      \"kerbside_proxy_cert_path\": \"${OVERRIDE}/cert.pem\",
      \"kerbside_proxy_key_path\": \"${OVERRIDE}/key.pem\",
      \"kerbside_cacert_path\": \"${OVERRIDE}/ca.pem\"
    }")"
    # And the loop over kerbside_reserved_ports, now empty too.
    [ "${SKIPPED}" = 4 ] || fail "expected only the feature-off message and the empty loops skipped, skipped=${SKIPPED}"

    CURRENT_CASE='case 2: validate passes one source of every type, and two Shaken Fist sources'
    VERBOSITY=-vvv validate_passes "${MULTI_VARS}"

    CURRENT_CASE='case 2: validate passes no kerbside_url without a Shaken Fist source'
    VERBOSITY=-vvv validate_passes "${NO_SF_VARS}"
}

case_3_required_empty() {
    local name
    for name in kerbside_public_fqdn kerbside_sql_url kerbside_auth_secret_seed; do
        CURRENT_CASE="case 3: validate refuses an empty ${name}"
        validate_fails "${name} is empty on localhost, but kerbside_hosts is not" \
            "$(write_vars "empty-${name}" "{\"${name}\": \"\"}")"
        assert_validate_refused
    done

    CURRENT_CASE='case 3: validate refuses an empty kerbside_sources'
    validate_fails 'kerbside_sources on localhost is empty, or not a list' \
        "$(write_vars empty-sources '{"kerbside_sources": []}')"
    assert_validate_refused

    CURRENT_CASE='case 3: validate refuses an empty kerbside_url with a Shaken Fist source'
    validate_fails 'kerbside_url is empty on localhost, but kerbside_sources has a source of type shakenfist \(sf, sf2\)' \
        "${MULTI_VARS}" "$(write_vars empty-url '{"kerbside_url": ""}')"
    assert_validate_refused
}

case_4_seed() {
    CURRENT_CASE='case 4a: validate refuses the sentinel seed'
    validate_fails "kerbside_auth_secret_seed on localhost is Kerbside's placeholder value" \
        "$(write_vars sentinel '{"kerbside_auth_secret_seed": "~~unconfigured~~"}')"
    assert_validate_refused

    CURRENT_CASE='case 4b: validate refuses a 31 character seed'
    VERBOSITY=-vvv validate_fails 'kerbside_auth_secret_seed on localhost is shorter than 32 characters' \
        "$(write_vars short-seed "{\"kerbside_auth_secret_seed\": \"${SEED:0:31}\"}")"
    assert_validate_refused
    assert_output_lacks "placeholder value"
}

case_5_ports() {
    # common.json reserves Shaken Fist's ports: 13000, 13001, 13005, 13006,
    # 13007 and the range 30000-65535.
    CURRENT_CASE='case 5a: validate refuses a reserved single port'
    validate_fails 'but kerbside_reserved_ports reserves 13000 there' "$(write_vars reserved-single '{
      "kerbside_api_port": 13000, "kerbside_metrics_port": 13001,
      "kerbside_vdi_secure_port": 13005, "kerbside_vdi_insecure_port": 13007
    }')"
    assert_validate_refused
    local port
    for port in 'kerbside_api_port is 13000|13000' 'kerbside_metrics_port is 13001|13001' \
            'kerbside_vdi_secure_port is 13005|13005' 'kerbside_vdi_insecure_port is 13007|13007'; do
        assert_output_has "${port%%|*} on localhost, but kerbside_reserved_ports reserves ${port#*|} there"
    done
    validate_fails 'kerbside_metrics_port is 13006 on localhost, but kerbside_reserved_ports reserves 13006 there' \
        "$(write_vars reserved-13006 '{"kerbside_metrics_port": 13006}')"
    assert_validate_refused

    CURRENT_CASE='case 5b: validate refuses a port in a reserved range, at either end'
    validate_fails 'but kerbside_reserved_ports reserves 30000-65535 there' "$(write_vars reserved-range '{
      "kerbside_api_port": 30000, "kerbside_vdi_secure_port": 30001,
      "kerbside_vdi_insecure_port": 40000, "kerbside_metrics_port": 65535
    }')"
    assert_validate_refused
    for port in kerbside_api_port=30000 kerbside_vdi_secure_port=30001 \
            kerbside_vdi_insecure_port=40000 kerbside_metrics_port=65535; do
        assert_output_has "${port%%=*} is ${port#*=} on localhost, but kerbside_reserved_ports reserves 30000-65535 there"
    done

    CURRENT_CASE='case 5b: validate passes the ports either side of reserved ones'
    validate_passes "$(write_vars reserved-beside '{
      "kerbside_api_port": 12999, "kerbside_vdi_secure_port": 13004,
      "kerbside_vdi_insecure_port": 13008, "kerbside_metrics_port": 29999
    }')"

    CURRENT_CASE='case 5b: validate names every entry which reserves a port'
    validate_fails 'kerbside_api_port is 13002 on localhost, but kerbside_reserved_ports reserves 13002, 13000-13010 there' \
        "$(write_vars reserved-twice '{"kerbside_reserved_ports": [13002, ["13000", "13010"]]}')"
    assert_validate_refused

    CURRENT_CASE='case 5c: validate refuses a malformed kerbside_reserved_ports entry'
    local entry
    for entry in '[1, 2, 3]' '"abc"' '[5, 4]' '0' '70000' '[1, 70000]' '{"low": 1}' 'true' \
            '[13000]' '13000.5'; do
        validate_fails "kerbside_reserved_ports entry 1 on localhost is .*, but each entry must be a port from 1 to 65535" \
            "$(write_vars reserved-malformed "{\"kerbside_reserved_ports\": [13000, ${entry}]}")"
        assert_validate_refused
    done

    CURRENT_CASE='case 5d: validate refuses two equal ports'
    validate_fails 'Two Kerbside ports on localhost are equal' \
        "$(write_vars equal-ports '{"kerbside_metrics_port": 5900}')"
    assert_validate_refused
    assert_output_has 'kerbside_vdi_secure_port=5900'
}

case_6_partial_overrides() {
    CURRENT_CASE='case 6: validate refuses a partial set of certificate overrides'
    validate_fails 'Only some of the Kerbside certificate override paths are set on localhost \(kerbside_proxy_cert_path\)' \
        "$(write_vars one-override "{\"kerbside_proxy_cert_path\": \"${OVERRIDE}/cert.pem\"}")"
    assert_validate_refused
    validate_fails 'kerbside_cacert_path is empty' "$(write_vars two-overrides "{
      \"kerbside_proxy_cert_path\": \"${OVERRIDE}/cert.pem\",
      \"kerbside_proxy_key_path\": \"${OVERRIDE}/key.pem\"
    }")"
    assert_validate_refused
}

case_7_sources() {
    # Every type's required fields, each source lacking all of them, so each
    # is named. The values are not secrets; case 18 searches for those.
    CURRENT_CASE="case 7a: validate refuses a Shaken Fist source's missing fields"
    sources_refused sf-fields '[{"source": "a", "type": "shakenfist"}]' \
        'source 0 (shakenfist): url is missing' 'source 0 (shakenfist): username is missing' \
        'source 0 (shakenfist): password is missing' 'source 0 (shakenfist): ca_cert is missing'

    CURRENT_CASE="case 7a: validate refuses an oVirt source's missing fields"
    sources_refused ovirt-fields '[{"source": "a", "type": "ovirt", "url": ""}]' \
        'source 0 (ovirt): url is empty' 'source 0 (ovirt): username is missing' \
        'source 0 (ovirt): password is missing' 'source 0 (ovirt): ca_cert is missing'

    CURRENT_CASE="case 7a: validate refuses an OpenStack source's missing fields"
    sources_refused openstack-fields '[{"source": "a", "type": "openstack"}]' \
        'source 0 (openstack): url is missing' 'source 0 (openstack): username is missing' \
        'source 0 (openstack): password is missing' 'source 0 (openstack): project_name is missing' \
        'source 0 (openstack): user_domain_id is missing' \
        'source 0 (openstack): project_domain_id is missing'

    CURRENT_CASE="case 7a: validate refuses a static source's missing fields"
    sources_refused static-fields '[
      {"source": "a", "type": "static"},
      {"source": "b", "type": "static", "consoles": {"uuid": "x"}},
      {"source": "c", "type": "static", "consoles": [
        "not-a-mapping",
        {"uuid": "x"},
        {"uuid": "x", "name": "n", "hypervisor": "h", "hypervisor_ip": ["i"],
         "insecure_port": 70000, "secure_port": "abc", "ticket": "t"}]}]' \
        'source 0 (static): consoles is missing; write consoles: [] for a source with none' \
        'source 1 (static): consoles is not a list' \
        'source 2 console 0 is not a mapping' \
        'source 2 console 1: name is missing' 'source 2 console 1: hypervisor is missing' \
        'source 2 console 1: hypervisor_ip is missing' \
        'source 2 console 1: insecure_port is missing' 'source 2 console 1: ticket is missing' \
        'source 2 console 2: hypervisor_ip is not text' \
        'source 2 console 2: insecure_port is not a port from 1 to 65535' \
        'source 2 console 2: secure_port is not a port from 1 to 65535'

    CURRENT_CASE='case 7a: validate passes a static source with no consoles'
    validate_passes "$(write_vars static-empty \
        '{"kerbside_sources": [{"source": "a", "type": "static", "consoles": []}]}')"

    CURRENT_CASE='case 7b: validate refuses a source with no name or type'
    sources_refused unnamed '[{"type": "static", "consoles": []}, {"source": "b"}]' \
        'source 0: source is missing, or is not non-empty text' \
        'source 1: type is missing, or is not non-empty text'

    # The argument specs refuse an entry which is not a mapping, before the
    # checker sees it, and without printing it (case 18).
    CURRENT_CASE='case 7b: validate refuses a source which is not a mapping'
    VERBOSITY=-vvv validate_fails "Elements value for option 'kerbside_sources' is of type str" \
        "$(write_vars not-mapping "{\"kerbside_sources\": [\"ticket ${STATIC_TICKET}\"]}")"
    assert_validate_refused

    CURRENT_CASE='case 7c: validate refuses a type Kerbside does not know'
    sources_refused unknown-type '[{"source": "a", "type": "vmware", "url": "u"}]' \
        'source 0: type is not one of openstack, ovirt, shakenfist, static'

    CURRENT_CASE='case 7d: validate refuses a duplicate source name'
    sources_refused duplicate '[
      {"source": "a", "type": "static", "consoles": []},
      {"source": "b", "type": "static", "consoles": []},
      {"source": "a", "type": "static", "consoles": []}]' \
        'sources 0 and 2 share a source name, which must be unique'

    CURRENT_CASE="case 7e: validate refuses a Shaken Fist source whose username is not system"
    sources_refused username '[{"source": "a", "type": "shakenfist", "url": "u",
      "username": "kerbside", "password": "p", "ca_cert": "c"}]' \
        'source 0 (shakenfist): username is not system, but Kerbside scrapes'

    CURRENT_CASE='case 7f: validate refuses a shared field which is not text'
    sources_refused not-text '[{"source": "a", "type": "openstack", "url": "u",
      "username": "n", "password": ["p"], "project_name": "s",
      "user_domain_id": true, "project_domain_id": "d"}]' \
        'source 0: password is not text' 'source 0: user_domain_id is not text'

    # The same checks, with secrets in every other source and at -vvv, for
    # case 18: a refusal must name positions, never print a value.
    CURRENT_CASE='case 7g: a refusal among secret-bearing sources names only positions'
    local multi_plus_dup
    multi_plus_dup="$("${PY}" -c '
import json, sys
sources = json.load(open(sys.argv[1]))["kerbside_sources"]
sources.append(dict(sources[1]))
print(json.dumps({"kerbside_sources": sources}))' "${MULTI_VARS}")"
    VERBOSITY=-vvv validate_fails 'sources.yaml refused: sources 1 and 5 share a source name' \
        "$(write_vars multi-dup "${multi_plus_dup}")"
    assert_validate_refused
}

case_8_local_wheels() {
    mkdir -p "${WORK}/wheel-checks"
    : > "${WORK}/wheel-checks/kerbside-0.8.0-py3-none-any.whl"
    : > "${WORK}/wheel-checks/kerbside-0.8.1-py3-none-any.whl"
    : > "${WORK}/wheel-checks/kerbside_proxy-0.8.0-py3-none-manylinux_2_28_x86_64.whl"
    : > "${WORK}/wheel-checks/gunicorn-23.0.0-py3-none-any.whl"

    CURRENT_CASE='case 8: validate passes a kerbside and a kerbside_proxy wheel'
    validate_passes "$(write_vars wheels-ok "{\"kerbside_local_wheels\": [
      \"${WORK}/wheel-checks/kerbside-0.8.0-py3-none-any.whl\",
      \"${WORK}/wheel-checks/kerbside_proxy-0.8.0-py3-none-manylinux_2_28_x86_64.whl\"]}")"

    CURRENT_CASE='case 8: validate refuses a wheel for no Kerbside package'
    validate_fails 'gunicorn-23.0.0-py3-none-any.whl, which is neither a kerbside wheel' \
        "$(write_vars wheels-other "{\"kerbside_local_wheels\": [
          \"${WORK}/wheel-checks/gunicorn-23.0.0-py3-none-any.whl\"]}")"
    assert_validate_refused

    CURRENT_CASE='case 8: validate refuses two wheels for one package'
    validate_fails 'lists more than one kerbside wheel \(kerbside-0.8.0-py3-none-any.whl, kerbside-0.8.1-py3-none-any.whl\)' \
        "$(write_vars wheels-two "{\"kerbside_local_wheels\": [
          \"${WORK}/wheel-checks/kerbside-0.8.0-py3-none-any.whl\",
          \"${WORK}/wheel-checks/kerbside-0.8.1-py3-none-any.whl\"]}")"
    assert_validate_refused

    CURRENT_CASE='case 8: validate refuses a wheel which is not on the control node'
    validate_fails 'kerbside_proxy-0.8.0-py3-none-any.whl, which is not a file on the control node' \
        "$(write_vars wheels-missing "{\"kerbside_local_wheels\": [
          \"${WORK}/nowhere/kerbside_proxy-0.8.0-py3-none-any.whl\"]}")"
    assert_validate_refused
}

# The files config hashes into the desired state, in its order.
DESIRED_FILE_LIST=("${CONF}/kerbside.ini" "${CONF}/sources.yaml" "${UNITS}/kerbside-api.service"
    "${UNITS}/kerbside-daemon.service" "${PKI}/server-cert.pem" "${PKI}/server-key.pem"
    "${PKI}/ca-cert.pem")

checksums() {
    sha256sum "${DESIRED_FILE_LIST[@]}"
}

case_9_ini() {
    CURRENT_CASE='case 9: config renders a kerbside.ini Kerbside can read'
    VERBOSITY=-vvv config_passes
    FIRST_DESIRED="${DESIRED}"
    local out
    out="$("${PY}" - "${CONF}/kerbside.ini" "${SQL_URL}" "${URL}" "${PKI}" << 'PYEOF' 2>&1
import configparser
import sys

path, sql_url, url, pki = sys.argv[1:]
# As kerbside/config.py reads it: interpolation off, every value literal.
parser = configparser.ConfigParser(interpolation=None)
if parser.read(path) != [path]:
    sys.exit('kerbside.ini could not be read')
values = {k: parser.get('kerbside', k) for k in parser.options('kerbside')}
expected = {
    'sql_url': sql_url,
    'sf_console_token_audience': url,
    'public_fqdn': 'console.example.com',
    'proxy_host_subject': 'O=Kerbside Test,CN=console.example.com',
    'proxy_host_cert_path': pki + '/server-cert.pem',
    'proxy_host_cert_key_path': pki + '/server-key.pem',
    'cacert_path': pki + '/ca-cert.pem',
    'node_name': 'localhost',
}
for key, want in expected.items():
    if values.get(key) != want:
        sys.exit(f'{key} reads back as {values.get(key)!r}, not {want!r}')
keystone = [k for k in values if 'keystone' in k]
if keystone:
    sys.exit(f'kerbside.ini has Keystone settings: {keystone}')
if parser.sections() != ['kerbside']:
    sys.exit(f'kerbside.ini has sections {parser.sections()}')
PYEOF
)" || fail "${out}"
    [ "$(stat -c %a "${CONF}/kerbside.ini")" = 640 ] \
        || fail "kerbside.ini has mode $(stat -c %a "${CONF}/kerbside.ini"), not 640"
    if grep -qF '%%' "${CONF}/kerbside.ini"; then
        fail "kerbside.ini doubles a %, which Kerbside reads literally"
    fi
}

# sources_match VARS_FILE: sources.yaml, loaded as Kerbside loads it, must
# equal kerbside_sources in VARS_FILE exactly, without printing either.
sources_match() {
    local out
    out="$(REPO_ROOT="${REPO_ROOT}" "${PY}" - "${CONF}/sources.yaml" "$1" << 'PYEOF' 2>&1
import importlib.util
import json
import os
import sys

# The checker's loader, which reads numbers as Kerbside does.
spec = importlib.util.spec_from_file_location(
    'checker', os.path.join(os.environ['REPO_ROOT'], 'ansible', 'roles',
                            'kerbside', 'files', 'kerbside-check-sources.py'))
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)

import yaml

with open(sys.argv[1]) as f:
    rendered = yaml.load(f, Loader=checker._SourcesLoader)
with open(sys.argv[2]) as f:
    wanted = json.load(f)['kerbside_sources']


def spelled(value):
    # Kerbside's loader keeps an unquoted number as the text written.
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, list):
        return [spelled(v) for v in value]
    if isinstance(value, dict):
        return {k: spelled(v) for k, v in value.items()}
    return value


if len(rendered) != len(wanted):
    sys.exit(f'sources.yaml has {len(rendered)} sources, not {len(wanted)}')
for index, (got, want) in enumerate(zip(rendered, wanted)):
    if sorted(got) != sorted(want):
        sys.exit(f'source {index} has keys {sorted(got)}, not {sorted(want)}')
    for key in want:
        if got[key] != spelled(want[key]):
            sys.exit(f'source {index} {key} does not load back as given')
PYEOF
)" || fail "${out}"
}

case_10_sources() {
    CURRENT_CASE='case 10: config renders a sources.yaml which loads back as kerbside_sources'
    sources_match "${WORK}/common.json"
    [ "$(stat -c %a "${CONF}/sources.yaml")" = 640 ] \
        || fail "sources.yaml has mode $(stat -c %a "${CONF}/sources.yaml"), not 640"

    CURRENT_CASE='case 10: config renders one source of every type, and two Shaken Fist sources'
    VERBOSITY=-vvv config_passes "${MULTI_VARS}"
    sources_match "${MULTI_VARS}"

    CURRENT_CASE='case 10: config renders an empty audience without a Shaken Fist source'
    VERBOSITY=-vvv config_passes "${NO_SF_VARS}"
    sources_match "${NO_SF_VARS}"
    grep -qx 'sf_console_token_audience = ' "${CONF}/kerbside.ini" \
        || fail 'kerbside.ini does not render the empty kerbside_url'

    # Back to common.json's, which case 11 starts from.
    config_passes
    [ "${DESIRED}" = "${FIRST_DESIRED}" ] || fail 'the desired state did not return to its first value'
}

# desired_step DESCRIPTION CHANGED_FILE_OR_NONE EDIT [extra vars file...]:
# run the command EDIT, then config with the vars, and check that exactly the
# one file changed and that the desired state is new.
SEEN_DESIRED=()
desired_step() {
    local what="$1" target="$2" edit="$3"
    shift 3
    CURRENT_CASE="case 11: the desired state follows ${what}"
    local before after changed
    before="$(checksums)"
    ${edit}
    config_passes "$@"
    after="$(checksums)"
    # diff exits 1 when the inputs differ, which is the expected case.
    changed="$({ diff <(echo "${before}") <(echo "${after}") || true; } | sed -n 's/^> [0-9a-f]* *//p')"
    [ "${changed}" = "${target}" ] \
        || fail "expected only '${target}' to change, but '${changed}' changed"
    local seen
    for seen in "${SEEN_DESIRED[@]}"; do
        [ "${DESIRED}" != "${seen}" ] || fail "the desired state did not change"
    done
    SEEN_DESIRED+=("${DESIRED}")
}

# The same key and subject, with a new serial: what a renewal looks like.
renew_cert() {
    cert proxy '/O=Kerbside Test/CN=console.example.com' proxy-ca 2
    cp "${WORK}/certs/proxy-cert.pem" "${PKI}/server-cert.pem"
}

case_11_desired_state() {
    CURRENT_CASE='case 11: the desired state is stable on a rerun'
    local base
    config_passes
    [ "${DESIRED}" = "${FIRST_DESIRED}" ] || fail 'the desired state changed on a rerun'
    [ "${CHANGED}" = 0 ] || fail "a rerun reported changed=${CHANGED}"
    local expected
    expected="$(IFS='|'; echo "${DESIRED_FILE_LIST[*]}")"
    [ "${DESIRED_FILES}" = "${expected}" ] \
        || fail "the desired state hashes ${DESIRED_FILES}, not ${expected}"
    base="$(checksums)"
    SEEN_DESIRED=("${FIRST_DESIRED}")

    # Cumulatively, one file at a time.
    local vars=()
    vars+=("$(write_vars workers '{"kerbside_api_workers": 3}')")
    desired_step 'kerbside_api_workers' "${UNITS}/kerbside-api.service" : "${vars[@]}"
    vars+=("$(write_vars fqdn '{"kerbside_public_fqdn": "console2.example.com"}')")
    desired_step 'kerbside_public_fqdn' "${CONF}/kerbside.ini" : "${vars[@]}"
    vars+=("$(write_vars source-url "{\"kerbside_sources\": [{\"source\": \"sf\",
      \"type\": \"shakenfist\", \"url\": \"https://sf-api.example.com:13000\",
      \"username\": \"system\", \"password\": \"${SYSTEM_KEY}\", \"ca_cert\": \"ca\"}]}")")
    desired_step "a source's url" "${CONF}/sources.yaml" : "${vars[@]}"
    desired_step 'a renewed certificate' "${PKI}/server-cert.pem" renew_cert "${vars[@]}"
    desired_step 'a replaced key' "${PKI}/server-key.pem" \
        "cp ${OVERRIDE}/key.pem ${PKI}/server-key.pem" "${vars[@]}"
    desired_step 'a replaced CA' "${PKI}/ca-cert.pem" \
        "cp ${OVERRIDE}/ca.pem ${PKI}/ca-cert.pem" "${vars[@]}"
    vars+=("$(write_vars code '{"kerbside_code_hash": "code-hash-2"}')")
    desired_step 'the installed code' '' : "${vars[@]}"

    CURRENT_CASE='case 11: the desired state returns when everything is restored'
    # Copied back rather than signed again: an ECDSA signature differs on
    # every signing.
    cp "${WORK}/certs/proxy-cert-first.pem" "${PKI}/server-cert.pem"
    cp "${WORK}/certs/proxy-key.pem" "${PKI}/server-key.pem"
    cp "${WORK}/certs/proxy-ca-cert.pem" "${PKI}/ca-cert.pem"
    config_passes
    [ "$(checksums)" = "${base}" ] || fail 'restoring everything did not restore the files'
    [ "${DESIRED}" = "${FIRST_DESIRED}" ] || fail 'the desired state did not return to its first value'
}

# refused CHECKED_FILE PATTERN [extra vars file...]: config must fail with
# PATTERN and leave CHECKED_FILE as it was, with nothing left behind.
refused() {
    local file="$1" pattern="$2"
    shift 2
    local before
    before="$(checksums)"
    VERBOSITY=-v config_fails "${pattern}" "$@"
    [ "$(checksums)" = "${before}" ] || fail "a refused render changed a file: $(checksums)"
    assert_output_has "The rendered ${file} was refused, so Kerbside keeps running with the file it has."
    local left
    left="$(find "${WORK}" -name '*.refused' -print)"
    [ -z "${left}" ] || fail "a refused render left ${left} behind"
}

case_12_refused_render() {
    CURRENT_CASE='case 12a: a kerbside.ini the checker refuses is not written'
    # A newline in a value would otherwise make a continuation line, or a
    # setting of its own.
    refused kerbside.ini 'kerbside.ini refused: public_fqdn spans more than one line' \
        "$(write_vars fqdn-newline '{"kerbside_public_fqdn": "console.example.com\n  injected = 1"}')"
    grep -qx 'public_fqdn = console.example.com' "${CONF}/kerbside.ini" \
        || fail 'kerbside.ini does not still have the old public_fqdn'

    CURRENT_CASE='case 12b: a sources.yaml the checker refuses is not written'
    # config does not run validate's checks, so the write is the last line of
    # defence. The other sources carry secrets, which the refusal must not
    # print (case 18).
    local multi_unknown
    multi_unknown="$("${PY}" -c '
import json, sys
sources = json.load(open(sys.argv[1]))["kerbside_sources"]
sources[3] = dict(sources[3], type="vmware")
print(json.dumps({"kerbside_sources": sources}))' "${MULTI_VARS}")"
    refused sources.yaml 'sources.yaml refused: source 3: type is not one of' \
        "$(write_vars multi-unknown "${multi_unknown}")"
}

case_13_overrides() {
    CURRENT_CASE='case 13: config uses the operator certificate override paths'
    config_passes "$(write_vars overrides "{
      \"kerbside_proxy_cert_path\": \"${OVERRIDE}/cert.pem\",
      \"kerbside_proxy_key_path\": \"${OVERRIDE}/key.pem\",
      \"kerbside_cacert_path\": \"${OVERRIDE}/ca.pem\"
    }")"
    local out
    out="$("${PY}" - "${CONF}/kerbside.ini" "${OVERRIDE}" << 'PYEOF' 2>&1
import configparser
import sys

parser = configparser.ConfigParser()
parser.read(sys.argv[1])
override = sys.argv[2]
expected = {
    'proxy_host_subject': 'C=AU,O=Operator\\, Inc.,CN=vdi.example.org',
    'proxy_host_cert_path': override + '/cert.pem',
    'proxy_host_cert_key_path': override + '/key.pem',
    'cacert_path': override + '/ca.pem',
}
for key, want in expected.items():
    got = parser.get('kerbside', key)
    if got != want:
        sys.exit(f'{key} is {got!r}, not {want!r}')
PYEOF
)" || fail "${out}"
    local expected
    expected="${CONF}/kerbside.ini|${CONF}/sources.yaml|${UNITS}/kerbside-api.service"
    expected+="|${UNITS}/kerbside-daemon.service|${OVERRIDE}/cert.pem|${OVERRIDE}/key.pem"
    expected+="|${OVERRIDE}/ca.pem"
    [ "${DESIRED_FILES}" = "${expected}" ] \
        || fail "the desired state hashes ${DESIRED_FILES}, not ${expected}"
}

# What the role rendered for Shaken Fist's deployment before it took any
# source: its one shakenfist source built from deploy_name sf, the default
# api_url, kerbside_system_key and kerbside_sf_ca_cert, on a co-located host.
# Recorded from the role as copied from Shaken Fist, with this script's
# values; @WORK@, @SYSTEM_KEY@, @SEED@ and @SQL_SECRET@ stand for them. Each
# file's first two lines, a comment naming the collection which wrote it,
# are left out, since the collection's name is all that changed there. One
# deliberate difference: the old role doubled the SQL URL's %, which Kerbside
# 0.7.0 and later read literally, so sql_url here keeps its single %.
cat > "${WORK}/shakenfist-sources.yaml.in" << 'EOF'
- ca_cert: '-----BEGIN CERTIFICATE-----

    MIIBszCCAVmgAwIBAgIUS2VyYnNpZGUgZXF1aXZhbGVuY2UgdGVzdCBDQTAKBggq

    hkjOPQQDAjAvMRQwEgYDVQQKDAtTaGFrZW4gRmlzdDEXMBUGA1UEAwwORXF1aXZh

    -----END CERTIFICATE-----

    '
  password: @SYSTEM_KEY@
  source: sf
  type: shakenfist
  url: http://localhost:13000
  username: system
EOF
cat > "${WORK}/shakenfist-kerbside.ini.in" << 'EOF'
[kerbside]
sql_url = mysql+pymysql://kerbside:pw%25@SQL_SECRET@@db.example.com/kerbside
auth_secret_seed = @SEED@
sources_path = @WORK@/etc/kerbside/sources.yaml
public_fqdn = console.example.com
cacert_path = @WORK@/etc/kerbside/pki/ca-cert.pem
proxy_host_cert_path = @WORK@/etc/kerbside/pki/server-cert.pem
proxy_host_cert_key_path = @WORK@/etc/kerbside/pki/server-key.pem
proxy_host_subject = O=Kerbside Test,CN=console.example.com
sf_console_token_audience = https://console.example.com:13002/kerbside/
public_secure_port = 5900
public_insecure_port = 5901
vdi_secure_port = 5900
vdi_insecure_port = 5901
prometheus_metrics_port = 13003
node_name = localhost
EOF

case_14_shakenfist_deployment() {
    CURRENT_CASE="case 14: Shaken Fist's deployment renders as it did before the role took any source"
    validate_passes "${SF_VARS}"
    config_passes "${SF_VARS}"
    local name out
    for name in sources.yaml kerbside.ini; do
        out="$(RENDER_WORK="${WORK}" SYSTEM_KEY="${SYSTEM_KEY}" SEED="${SEED}" SQL_SECRET="${SQL_SECRET}" \
            "${PY}" - "${WORK}/shakenfist-${name}.in" "${CONF}/${name}" << 'PYEOF' 2>&1
import os
import sys

with open(sys.argv[1]) as f:
    expected = f.read()
for key, name in (('WORK', 'RENDER_WORK'), ('SYSTEM_KEY', 'SYSTEM_KEY'),
                  ('SEED', 'SEED'), ('SQL_SECRET', 'SQL_SECRET')):
    expected = expected.replace('@%s@' % key, os.environ[name])
with open(sys.argv[2]) as f:
    lines = f.read().split('\n')
if not all(line.startswith('# ') for line in lines[:2]):
    sys.exit('%s does not start with its two comment lines' % sys.argv[2])
if '\n'.join(lines[2:]) != expected:
    # The line numbers only: the file holds secrets.
    got = lines[2:]
    want = expected.split('\n')
    differ = [str(i + 3) for i in range(max(len(got), len(want)))
              if i >= len(got) or i >= len(want) or got[i] != want[i]]
    sys.exit('%s differs from the earlier render at lines %s'
             % (sys.argv[2], ', '.join(differ)))
PYEOF
)" || fail "${out}"
    done
}

# bootstrap's virtualenv, a stub: its Python only answers bootstrap's
# site-packages question, its pip does nothing, and its uv records what it
# was asked to install, unpacks any wheel among it, and freezes
# ${WORK}/freeze.txt, with any wheel it installed as a file URL in place of
# that package's line, or fails to when ${WORK}/uv-freeze-fails exists. uv
# refuses to run without VIRTUAL_ENV set to the virtualenv, as the real one
# would then look elsewhere. bin/activate exists, so bootstrap does not create
# the virtualenv.
BVENV="${WORK}/bvenv"
BSITE="${BVENV}/lib/site-packages"
mkdir -p "${BVENV}/bin" "${BSITE}/kerbside/__pycache__" "${BSITE}/shakenfist_client"
: > "${BVENV}/bin/activate"
printf '#!/bin/sh\necho %s\n' "'${BSITE}'" > "${BVENV}/bin/python"
printf '#!/bin/sh\nexit 0\n' > "${BVENV}/bin/pip"
cat > "${BVENV}/bin/uv" << EOF
#!/bin/sh
if [ "\${VIRTUAL_ENV:-}" != '${BVENV}' ]; then
    echo "uv stub: VIRTUAL_ENV is '\${VIRTUAL_ENV:-}', not the virtualenv" >&2
    exit 2
fi
case "\$1 \$2" in
    'pip install')
        shift 2
        printf '%s\n' "\$@" > '${WORK}/uv-install-args'
        for arg in "\$@"; do
            case "\${arg##*/}" in
                kerbside_proxy-*.whl) '${PY}' -m zipfile -e "\${arg}" '${BVENV}/bin' ;;
                kerbside-*.whl) '${PY}' -m zipfile -e "\${arg}" '${BSITE}' ;;
            esac
        done ;;
    'pip freeze')
        if [ -f '${WORK}/uv-freeze-fails' ]; then
            echo 'uv stub: freeze failed' >&2
            exit 1
        fi
        wheels="\$(grep '[.]whl\$' '${WORK}/uv-install-args' || true)"
        for wheel in \${wheels}; do
            case "\${wheel##*/}" in
                kerbside_proxy-*) echo "kerbside-proxy @ file://\${wheel}" ;;
                kerbside-*) echo "kerbside @ file://\${wheel}" ;;
            esac
        done
        if echo "\${wheels}" | grep -q '/kerbside-[^/]*\$'; then
            grep -v '^kerbside==' '${WORK}/freeze.txt'
        else
            cat '${WORK}/freeze.txt'
        fi ;;
    *) echo "uv stub: unexpected arguments: \$*" >&2; exit 2 ;;
esac
EOF
chmod +x "${BVENV}/bin/python" "${BVENV}/bin/pip" "${BVENV}/bin/uv"
: > "${WORK}/uv-install-args"

# The installed code, as files whose contents a case can change.
install_stub_code() {
    rm -rf "${BSITE}/kerbside"
    mkdir -p "${BSITE}/kerbside/__pycache__" "${BSITE}/shakenfist_client"
    echo 'kerbside 0.7.0' > "${BSITE}/kerbside/__init__.py"
    echo 'kerbside.db 0.7.0' > "${BSITE}/kerbside/db.py"
    echo 'bytecode at time 1' > "${BSITE}/kerbside/__pycache__/db.cpython-313.pyc"
    echo 'shakenfist_client 0.8.0' > "${BSITE}/shakenfist_client/__init__.py"
    echo 'kerbside-proxy 0.7.0' > "${BVENV}/bin/kerbside-proxy"
    write_freeze kerbside==0.7.0 gunicorn==23.0.0 pip==26.2.1 shakenfist-client==0.8.0 \
        sqlalchemy==2.0.40 uv==0.12.23
}

# write_freeze LINE...: what uv pip freeze prints, in the order given.
write_freeze() {
    printf '%s\n' "$@" > "${WORK}/freeze.txt"
}

# bootstrap's extra vars: no kerbside_code_hash, since an extra var would
# outrank the fact bootstrap sets, and the stub virtualenv. Its one source is
# a Shaken Fist one, so the client is installed and hashed.
SYSTEM_KEY="${SYSTEM_KEY}" USER_NAME="$(id -un)" GROUP_NAME="$(id -gn)" STATE="${STATE}" \
    BVENV="${BVENV}" "${PY}" - "${WORK}/bootstrap-common.json" << 'PYEOF2'
import json
import os
import sys

env = os.environ
with open(sys.argv[1], 'w') as f:
    json.dump({
        'kerbside_sources': [{
            'source': 'sf', 'type': 'shakenfist',
            'url': 'http://localhost:13000', 'username': 'system',
            'password': env['SYSTEM_KEY'], 'ca_cert': 'ca'}],
        'kerbside_state_dir': env['STATE'],
        'kerbside_venv': env['BVENV'],
        'kerbside_user': env['USER_NAME'],
        'kerbside_group': env['GROUP_NAME'],
        'kerbside_file_owner': env['USER_NAME'],
        'kerbside_file_group': env['GROUP_NAME'],
    }, f, indent=2)
PYEOF2
STATIC_ONLY_VARS="$(write_vars static-only \
    '{"kerbside_sources": [{"source": "lab", "type": "static", "consoles": []}]}')"

# run_bootstrap [extra vars file...]: bootstrap against the stub virtualenv,
# without its apt, user and group tasks. Returns its status, and leaves the
# hash in CODE_HASH.
run_bootstrap() {
    local rc=0
    ANSIBLE_SKIP_TAGS=packages,system-users COMMON_VARS="${WORK}/bootstrap-common.json" \
        run_ansible "${WORK}/bootstrap.yml" "$@" || rc=$?
    CODE_HASH="$(sed -n 's/.*"msg": "CODE_HASH=\([0-9a-f]\{64\}\)".*/\1/p' "${LAST_LOG}")"
    return "${rc}"
}

# installed_has / installed_lacks ARG: what bootstrap last asked uv to
# install, one argument a line.
installed_has() {
    grep -qxF -- "$1" "${WORK}/uv-install-args" \
        || fail "bootstrap did not install $1: $(tr '\n' ' ' < "${WORK}/uv-install-args")"
}

installed_lacks() {
    if grep -qxF -- "$1" "${WORK}/uv-install-args"; then
        fail "bootstrap installed $1"
    fi
}

# code_hash_step DESCRIPTION same|new EDIT...: run the command EDIT, then
# bootstrap with ${STEP_VARS[@]}, and check that the code hash is the first
# one, or one not seen before.
SEEN_CODE_HASHES=()
STEP_VARS=()
code_hash_step() {
    local what="$1" expect="$2"
    shift 2
    CURRENT_CASE="${CODE_HASH_CASE}: the code hash after ${what}"
    "$@"
    run_bootstrap "${STEP_VARS[@]}" || fail 'bootstrap failed'
    [ -n "${CODE_HASH}" ] || fail 'bootstrap did not report a code hash'
    local seen
    if [ "${expect}" = same ]; then
        [ "${CODE_HASH}" = "${FIRST_CODE_HASH}" ] \
            || fail "the code hash changed, but ${what} must not restart Kerbside"
    else
        for seen in "${SEEN_CODE_HASHES[@]}"; do
            [ "${CODE_HASH}" != "${seen}" ] \
                || fail "the code hash did not change, but ${what} must restart Kerbside"
        done
        SEEN_CODE_HASHES+=("${CODE_HASH}")
    fi
}

case_15_bootstrap_code_hash() {
    CODE_HASH_CASE='case 15'
    STEP_VARS=()
    CURRENT_CASE="case 15: bootstrap computes a code hash"
    install_stub_code
    run_bootstrap || fail 'bootstrap failed'
    [ -n "${CODE_HASH}" ] || fail 'bootstrap did not report a code hash'
    FIRST_CODE_HASH="${CODE_HASH}"
    SEEN_CODE_HASHES=("${CODE_HASH}")
    installed_has 'kerbside>=0.7.0'
    installed_has gunicorn
    installed_has shakenfist-client

    code_hash_step 'a rerun' same :
    code_hash_step 'uv listing packages in another order' same \
        write_freeze uv==0.12.23 sqlalchemy==2.0.40 shakenfist-client==0.8.0 pip==26.2.1 \
        gunicorn==23.0.0 kerbside==0.7.0
    code_hash_step 'a recompiled .pyc' same \
        eval "echo 'bytecode at time 2' > '${BSITE}/kerbside/__pycache__/db.cpython-313.pyc'"
    code_hash_step 'a pip and uv upgrade' same \
        write_freeze kerbside==0.7.0 gunicorn==23.0.0 pip==26.3 shakenfist-client==0.8.0 \
        sqlalchemy==2.0.40 uv==0.13.0
    code_hash_step 'a dependency-only upgrade' new \
        write_freeze kerbside==0.7.0 gunicorn==23.0.0 pip==26.2.1 shakenfist-client==0.8.0 \
        sqlalchemy==2.0.41 uv==0.12.23
    code_hash_step 'everything restored' same install_stub_code
    code_hash_step 'a rebuilt kerbside wheel with an unchanged version' new \
        eval "echo 'kerbside.db 0.7.0, rebuilt' > '${BSITE}/kerbside/db.py'"
    code_hash_step 'a rebuilt kerbside-proxy wheel with an unchanged version' new \
        eval "install_stub_code; echo 'kerbside-proxy 0.7.0, rebuilt' > '${BVENV}/bin/kerbside-proxy'"
    code_hash_step 'a changed Shaken Fist client' new \
        eval "install_stub_code; echo 'shakenfist_client 0.8.0, patched' > '${BSITE}/shakenfist_client/__init__.py'"

    CURRENT_CASE="case 15: bootstrap fails when uv pip freeze fails"
    install_stub_code
    : > "${WORK}/uv-freeze-fails"
    if run_bootstrap; then
        fail 'bootstrap succeeded although uv pip freeze failed'
    fi
    rm -f "${WORK}/uv-freeze-fails"
    assert_output_has 'uv stub: freeze failed'
    [ -z "${CODE_HASH}" ] || fail 'bootstrap reported a code hash although uv pip freeze failed'

    CURRENT_CASE="case 15: bootstrap fails when the kerbside package is missing"
    mv "${BSITE}/kerbside" "${WORK}/kerbside.moved"
    if run_bootstrap; then
        fail 'bootstrap succeeded although kerbside is not installed'
    fi
    mv "${WORK}/kerbside.moved" "${BSITE}/kerbside"
    [ -z "${CODE_HASH}" ] || fail 'bootstrap reported a code hash although a package is missing'

    CURRENT_CASE="case 15: bootstrap fails when a Shaken Fist source's client is missing"
    mv "${BSITE}/shakenfist_client" "${WORK}/shakenfist_client.moved"
    if run_bootstrap; then
        fail 'bootstrap succeeded although shakenfist_client is not installed'
    fi
    [ -z "${CODE_HASH}" ] || fail 'bootstrap reported a code hash although a package is missing'

    # The client stays moved away: without a Shaken Fist source it is neither
    # installed nor hashed, so its absence fails nothing.
    CURRENT_CASE="case 15: bootstrap neither installs nor needs the client without a Shaken Fist source"
    run_bootstrap "${STATIC_ONLY_VARS}" || fail 'bootstrap failed without shakenfist_client'
    [ -n "${CODE_HASH}" ] || fail 'bootstrap did not report a code hash'
    installed_lacks shakenfist-client
    installed_has 'kerbside>=0.7.0'
    local without_client="${CODE_HASH}"
    mv "${WORK}/shakenfist_client.moved" "${BSITE}/shakenfist_client"
    run_bootstrap "${STATIC_ONLY_VARS}" || fail 'bootstrap failed'
    [ "${CODE_HASH}" = "${without_client}" ] \
        || fail 'an installed client changed the hash although no source needs it'
}

# make_wheel PATH CONTENT: a stand-in wheel at PATH, a zip file holding the
# package files the real wheel would, each saying CONTENT, with a fixed
# timestamp so the same CONTENT gives the same bytes.
make_wheel() {
    mkdir -p "$(dirname "$1")"
    "${PY}" - "$1" "$2" << 'PYEOF'
import os
import sys
import zipfile

path, content = sys.argv[1:]
if os.path.basename(path).startswith('kerbside_proxy-'):
    members = {'kerbside-proxy': content}
else:
    members = {'kerbside/__init__.py': content, 'kerbside/db.py': content}
with zipfile.ZipFile(path, 'w') as z:
    for name, text in members.items():
        z.writestr(zipfile.ZipInfo(name, (2020, 1, 1, 0, 0, 0)), text + '\n')
PYEOF
}

case_16_local_wheels() {
    local kw='kerbside-0.8.0.dev1-py3-none-any.whl'
    local pw='kerbside_proxy-0.8.0.dev1-py3-none-manylinux_2_28_x86_64.whl'
    make_wheel "${WORK}/wheels-a/${kw}" 'kerbside wheel 1'
    make_wheel "${WORK}/wheels-a/${pw}" 'kerbside-proxy wheel 1'

    CURRENT_CASE='case 16: bootstrap copies and installs local wheels'
    install_stub_code
    run_bootstrap "$(write_vars wheels-a "{\"kerbside_local_wheels\": [
      \"${WORK}/wheels-a/${kw}\", \"${WORK}/wheels-a/${pw}\"]}")" || fail 'bootstrap failed'
    # Each from a copy in kerbside_state_dir/wheels.
    local wheel installed
    for wheel in "${kw}" "${pw}"; do
        installed="$(grep -F "/${wheel}" "${WORK}/uv-install-args" || true)"
        [ -n "${installed}" ] \
            || fail "bootstrap did not install ${wheel}: $(tr '\n' ' ' < "${WORK}/uv-install-args")"
        case "${installed}" in
            "${STATE}/wheels/"*) ;;
            *) fail "bootstrap installed ${wheel} from ${installed}, not from ${STATE}/wheels" ;;
        esac
        cmp -s "${WORK}/wheels-a/${wheel}" "${installed}" \
            || fail "${installed} is not a copy of the control node's ${wheel}"
    done
    installed_lacks 'kerbside>=0.7.0'
    installed_has gunicorn
    installed_has shakenfist-client
    grep -qx 'kerbside wheel 1' "${BSITE}/kerbside/db.py" \
        || fail 'the kerbside wheel was not installed'
    grep -qx 'kerbside-proxy wheel 1' "${BVENV}/bin/kerbside-proxy" \
        || fail 'the kerbside_proxy wheel was not installed'
    FIRST_CODE_HASH="${CODE_HASH}"
    SEEN_CODE_HASHES=("${CODE_HASH}")

    CODE_HASH_CASE='case 16'
    STEP_VARS=("${WORK}/vars/wheels-a.json")
    code_hash_step 'the same wheels again' same :
    assert_output_lacks "changed: [localhost] => (item=${WORK}/wheels-a/"

    # The same bytes from elsewhere on the control node, with a new mtime.
    mkdir -p "${WORK}/wheels-b"
    cp "${WORK}/wheels-a/${kw}" "${WORK}/wheels-a/${pw}" "${WORK}/wheels-b/"
    touch -d '2021-01-01' "${WORK}/wheels-b/${kw}"
    STEP_VARS=("$(write_vars wheels-b "{\"kerbside_local_wheels\": [
      \"${WORK}/wheels-b/${kw}\", \"${WORK}/wheels-b/${pw}\"]}")")
    code_hash_step 'the same wheels from another directory' same :

    code_hash_step 'a rebuilt kerbside wheel' new \
        make_wheel "${WORK}/wheels-b/${kw}" 'kerbside wheel 2'
    code_hash_step 'a rebuilt kerbside_proxy wheel' new \
        make_wheel "${WORK}/wheels-b/${pw}" 'kerbside-proxy wheel 2'

    CURRENT_CASE='case 16: a kerbside_proxy wheel alone replaces only the proxy package'
    rm -rf "${WORK}/wheels-c"
    make_wheel "${WORK}/wheels-c/${pw}" 'kerbside-proxy wheel 3'
    run_bootstrap "$(write_vars wheels-c "{\"kerbside_local_wheels\": [
      \"${WORK}/wheels-c/${pw}\"], \"kerbside_proxy_package\": \"kerbside-proxy==0.7.0\"}")" \
        || fail 'bootstrap failed'
    installed_has 'kerbside>=0.7.0'
    installed_lacks 'kerbside-proxy==0.7.0'
    grep -qF "/${pw}" "${WORK}/uv-install-args" || fail "bootstrap did not install ${pw}"
}

# The readiness check's runuser, a stub on PATH: it records its arguments,
# one a line, and answers as kerbside-ready.py would for keys fetched a
# minute from now, so the first check passes.
STUB_BIN="${WORK}/stub-bin"
mkdir -p "${STUB_BIN}"
cat > "${STUB_BIN}/runuser" << EOF
#!/bin/sh
printf '%s\n' "\$@" > '${WORK}/runuser-args'
echo "{\"errored\": false, \"fetched_at\": \$((\$(date +%s) + 60))}"
EOF
chmod +x "${STUB_BIN}/runuser"

# run_register [extra vars file...]: register without the migration and the
# units, against the stub runuser. Returns its status.
run_register() {
    rm -f "${WORK}/runuser-args" "${STATE}/.deployed-state.sha256"
    local rc=0
    PATH="${STUB_BIN}:${PATH}" ANSIBLE_SKIP_TAGS=kerbside-database,kerbside-services \
        run_ansible "${WORK}/register.yml" \
        "$(write_vars register '{"kerbside_desired_state": "desired-state-1",
          "kerbside_ready_retries": 2}')" "$@" || rc=$?
    return "${rc}"
}

case_17_readiness() {
    CURRENT_CASE='case 17: register waits on every Shaken Fist source, and only those'
    VERBOSITY=-vvv run_register "${MULTI_VARS}" || fail 'register failed'
    [ -f "${WORK}/runuser-args" ] || fail 'register did not run the readiness check'
    local expected
    expected="$(printf '%s\n' -u "$(id -un)" -- "${VENV}/bin/python" \
        "${STATE}/bin/kerbside-ready.py" sf sf2)"
    [ "$(cat "${WORK}/runuser-args")" = "${expected}" ] \
        || fail "the readiness check was run as: $(tr '\n' ' ' < "${WORK}/runuser-args")"
    grep -qx 'desired-state-1' "${STATE}/.deployed-state.sha256" \
        || fail 'register did not record the desired state once ready'

    CURRENT_CASE='case 17: register waits on no signing keys without a Shaken Fist source'
    VERBOSITY=-vvv run_register "${NO_SF_VARS}" || fail 'register failed'
    [ ! -e "${WORK}/runuser-args" ] || fail 'register ran the readiness check with no Shaken Fist source'
    assert_output_has 'No source is of type shakenfist, so there are no console token signing'
    grep -qx 'desired-state-1' "${STATE}/.deployed-state.sha256" \
        || fail 'register did not record the desired state once ready'
}

case_18_secrets() {
    CURRENT_CASE='case 18: no secret reaches the ansible output'
    LAST_LOG=''
    # Prove the verbose runs happened, with every source type, or their
    # absence of secrets proves nothing.
    grep -lq 'ESTABLISH LOCAL CONNECTION' "${WORK}"/logs/*.log \
        || fail 'no run was verbose'
    grep -l 'ESTABLISH LOCAL CONNECTION' "${WORK}"/logs/*.log \
        | xargs grep -lqF "Check kerbside_sources by Kerbside's rules" \
        || fail 'no validate run was verbose'
    local secret
    for secret in "${SECRETS[@]}"; do
        if grep -lF -- "${secret}" "${WORK}"/logs/*.log > "${WORK}/leaks" 2>&1; then
            fail "a secret reached the output of $(tr '\n' ' ' < "${WORK}/leaks")"
        fi
    done
}

START="${SECONDS}"
case_1_feature_off
case_2_valid
case_3_required_empty
case_4_seed
case_5_ports
case_6_partial_overrides
case_7_sources
case_8_local_wheels
case_9_ini
case_10_sources
case_11_desired_state
case_12_refused_render
case_13_overrides
case_14_shakenfist_deployment
case_15_bootstrap_code_hash
case_16_local_wheels
case_17_readiness
case_18_secrets

echo "kerbside role: all eighteen cases passed (${RUNS} ansible runs, $((SECONDS - START))s)"
