#!/bin/bash
#
# ci-test-ansible-role.sh -- drive the shakenfist.kerbside collection's
# kerbside role through its validate, bootstrap and config entry points
# against localhost, and check what they do.
#
# It proves that validate refuses each configuration the role cannot
# deploy, each with its own message, and passes a correct one and an empty
# kerbside group, and that a Kerbside port one of Shaken Fist's daemons uses
# is refused on a co-located host only; that bootstrap's code hash follows
# every package version in the virtualenv and the installed files, but not
# pip's, uv's, __pycache__ or the freeze order; that config renders a
# kerbside.ini which configparser reads back with interpolation (a % in
# kerbside_sql_url included), whose token audience is kerbside_url byte for
# byte, and a sources.yaml whose ca_cert is kerbside_sf_ca_cert byte for
# byte; that a render either checker refuses leaves the running file in
# place and nothing behind; that the desired-state hash is stable across
# reruns, follows every file Kerbside runs with, and returns to its first
# value when they are restored; and that the secrets never reach the
# ansible output.
#
# register is not run: it needs systemd, MariaDB and a console source's
# API. bootstrap runs against a stub virtualenv whose pip and uv install
# nothing, since a real install needs PyPI, and with the apt, user and group
# tasks skipped by tag; the other cases are given kerbside_code_hash, which
# it sets, as an extra var instead.
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

# The proxy CA and certificate, installed where internal_ca would put them,
# and a second pair for the operator override paths, with a subject of its
# own so a render can be told apart. The CA which Shaken Fist's /admin/cacert
# serves is a third.
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

URL='https://console.example.com:13002/kerbside/'
FQDN='console.example.com'
# The secrets. The seed is exactly 32 characters, validate's minimum. The SQL
# URL's password carries a %, which the INI must double; its distinctive part
# is what the output is searched for, so that a doubled copy is found too.
SYSTEM_KEY='kb-system-key-Vt7qL2mXc9Rw'
SEED='seed-Jk4pW8zN2bQ6vT1yH5cR9mD3fL7'
SQL_SECRET='Xq8Tz3LmPw'
SQL_URL="mysql+pymysql://kerbside:pw%25${SQL_SECRET}@db.example.com/kerbside"
[ "${#SEED}" -eq 32 ] || fail "the test seed is ${#SEED} characters, not 32"
SECRETS=("${SYSTEM_KEY}" "${SEED}" "${SEED:0:31}" "${SQL_SECRET}")

SF_CA_FILE="${WORK}/certs/sf-ca-cert.pem"

# Every run gets these: a valid configuration, as a co-located Kerbside host
# sees it. The CA is multi-line, so the file is written by python, which reads
# the values from its environment.
URL="${URL}" FQDN="${FQDN}" SYSTEM_KEY="${SYSTEM_KEY}" SEED="${SEED}" SQL_URL="${SQL_URL}" \
    SF_CA_FILE="${SF_CA_FILE}" CONF="${CONF}" STATE="${STATE}" VENV="${VENV}" UNITS="${UNITS}" \
    USER_NAME="$(id -un)" GROUP_NAME="$(id -gn)" \
    "${PY}" - "${WORK}/common.json" << 'PYEOF'
import json
import os
import sys

env = os.environ
with open(env['SF_CA_FILE']) as f:
    sf_ca = f.read()
with open(sys.argv[1], 'w') as f:
    json.dump({
        'kerbside_url': env['URL'],
        'kerbside_url_on_sf_nodes': env['URL'],
        'kerbside_public_fqdn': env['FQDN'],
        'kerbside_system_key': env['SYSTEM_KEY'],
        'kerbside_auth_secret_seed': env['SEED'],
        'kerbside_sql_url': env['SQL_URL'],
        'kerbside_sf_ca_cert': sf_ca,
        'kerbside_hosts': ['localhost'],
        'kerbside_colocated': True,
        'kerbside_code_hash': 'code-hash-1',
        'kerbside_config_dir': env['CONF'],
        'kerbside_state_dir': env['STATE'],
        'kerbside_venv': env['VENV'],
        'kerbside_unit_dir': env['UNITS'],
        'kerbside_user': env['USER_NAME'],
        'kerbside_group': env['GROUP_NAME'],
        'kerbside_file_owner': env['USER_NAME'],
        'kerbside_file_group': env['GROUP_NAME'],
    }, f, indent=2)
PYEOF

cat > "${WORK}/validate.yml" << 'EOF'
---
- name: Run the kerbside role's validate entry point
  hosts: localhost
  connection: local
  gather_facts: false
  tasks:
    - name: Validate the Kerbside configuration
      ansible.builtin.include_role:
        name: shakenfist.kerbside.kerbside
        tasks_from: validate
EOF

# config, then the desired state it computed and the files that went into it,
# on lines of their own for the script to read.
cat > "${WORK}/config.yml" << 'EOF'
---
- name: Run the kerbside role's config entry point
  hosts: localhost
  connection: local
  gather_facts: false
  tasks:
    - name: Configure Kerbside
      ansible.builtin.include_role:
        name: shakenfist.kerbside.kerbside
        tasks_from: config

    - name: Report the desired state
      ansible.builtin.debug:
        msg: "DESIRED_STATE={{ kerbside_desired_state }}"

    - name: Report the files hashed into the desired state
      ansible.builtin.debug:
        msg: "DESIRED_FILES={{ kerbside_config_stats.results | map(attribute='item') | join('|') }}"
EOF

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

case_1_feature_off() {
    CURRENT_CASE='case 1: validate passes an empty kerbside group'
    # Everything else empty too: none of it applies without the group.
    validate_passes "$(write_vars off '{
      "kerbside_hosts": [], "kerbside_url": "", "kerbside_url_on_sf_nodes": "",
      "kerbside_system_key": "", "kerbside_auth_secret_seed": "~~unconfigured~~",
      "kerbside_api_port": 40000, "kerbside_proxy_cert_path": "/x"
    }')"
    assert_output_has 'The kerbside group is empty, so Kerbside is not being deployed'
    assert_output_lacks 'kerbside_url is set'

    # kerbside_url alone is a Kerbside deployed some other way.
    validate_passes "$(write_vars byo '{"kerbside_hosts": []}')"
    assert_output_has 'Shaken Fist will use a Kerbside deployed some other way'
}

case_2_valid() {
    CURRENT_CASE='case 2: validate passes a valid configuration'
    # Co-located with the loopback default api_url, at -vvv for the secrets
    # search. Only the feature-off message is skipped.
    VERBOSITY=-vvv validate_passes
    [ "${SKIPPED}" = 1 ] || fail "expected only the feature-off message skipped, skipped=${SKIPPED}"
    assert_output_lacks 'The kerbside group is empty'

    # A dedicated host with a routable api_url, all three overrides, and the
    # highest legal port.
    validate_passes "$(write_vars valid-dedicated "{
      \"kerbside_colocated\": false,
      \"api_url\": \"https://sf-api.example.com:13000\",
      \"kerbside_metrics_port\": 29999,
      \"kerbside_proxy_cert_path\": \"${OVERRIDE}/cert.pem\",
      \"kerbside_proxy_key_path\": \"${OVERRIDE}/key.pem\",
      \"kerbside_cacert_path\": \"${OVERRIDE}/ca.pem\"
    }")"
    [ "${SKIPPED}" = 1 ] || fail "expected only the feature-off message skipped, skipped=${SKIPPED}"

    # Not supplied at all, as by a playbook other than site.yml: no check.
    validate_passes "$(write_vars not-supplied '{"kerbside_url_on_sf_nodes": null}')"
}

case_3_required_empty() {
    local name
    for name in kerbside_url kerbside_system_key kerbside_public_fqdn kerbside_sql_url \
            kerbside_auth_secret_seed; do
        CURRENT_CASE="case 3: validate refuses an empty ${name}"
        validate_fails "${name} is empty on localhost, but the kerbside group is not" \
            "$(write_vars "empty-${name}" "{\"${name}\": \"\"}")"
        assert_validate_refused
    done
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
    CURRENT_CASE='case 5a: validate refuses a port in the instance console range'
    validate_fails 'every Kerbside port must be below 30000' "$(write_vars high-ports '{
      "kerbside_api_port": 30000, "kerbside_vdi_secure_port": 30001,
      "kerbside_vdi_insecure_port": 40000, "kerbside_metrics_port": 65535
    }')"
    assert_validate_refused
    local port
    for port in 'kerbside_api_port is 30000' 'kerbside_vdi_secure_port is 30001' \
            'kerbside_vdi_insecure_port is 40000' 'kerbside_metrics_port is 65535'; do
        assert_output_has "${port} on localhost, but every Kerbside port must be below 30000"
    done

    CURRENT_CASE='case 5b: validate refuses two equal ports'
    validate_fails 'Two Kerbside ports on localhost are equal' \
        "$(write_vars equal-ports '{"kerbside_metrics_port": 5900}')"
    assert_validate_refused
    assert_output_has 'kerbside_vdi_secure_port=5900'

    # Every port in kerbside_sf_listener_ports, across two runs since there
    # are five of them and four Kerbside ports. common.json's host is
    # co-located.
    CURRENT_CASE="case 5c: validate refuses a Shaken Fist daemon's port on a co-located host"
    validate_fails 'but localhost is also a Shaken Fist node, where' "$(write_vars sf-ports '{
      "kerbside_api_port": 13000, "kerbside_metrics_port": 13001,
      "kerbside_vdi_secure_port": 13005, "kerbside_vdi_insecure_port": 13007
    }')"
    assert_validate_refused
    local listener
    for listener in 'kerbside_api_port is 13000|sf-api' \
            "kerbside_metrics_port is 13001|sf-resources' metrics (RESOURCES_METRICS_PORT)" \
            "kerbside_vdi_secure_port is 13005|sf-database's gRPC gateway (MARIADB_GATEWAY_PORT)" \
            "kerbside_vdi_insecure_port is 13007|sf-cluster's metrics (CLUSTER_METRICS_PORT)"; do
        assert_output_has "${listener%%|*}, but localhost is also a Shaken Fist node, where ${listener#*|} listens on that port."
    done
    validate_fails "kerbside_metrics_port is 13006, but localhost is also a Shaken Fist node, where sf-database's metrics \\(MARIADB_GATEWAY_METRICS_PORT\\) listens" \
        "$(write_vars sf-port-13006 '{"kerbside_metrics_port": 13006}')"
    assert_validate_refused

    CURRENT_CASE="case 5c: validate passes a Shaken Fist daemon's port on a dedicated host"
    validate_passes "$(write_vars sf-ports-dedicated '{
      "kerbside_colocated": false,
      "api_url": "https://sf-api.example.com:13000",
      "kerbside_api_port": 13000, "kerbside_metrics_port": 13001,
      "kerbside_vdi_secure_port": 13005, "kerbside_vdi_insecure_port": 13007
    }')"
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

case_7_loopback_api_url() {
    local url
    for url in 'http://localhost:13000' 'http://127.0.0.1:13000' 'http://[::1]:13000'; do
        CURRENT_CASE="case 7: validate refuses api_url ${url} on a dedicated Kerbside host"
        validate_fails 'a loopback address, but localhost is not a Shaken Fist node' \
            "$(write_vars loopback "{
          \"kerbside_colocated\": false, \"api_url\": \"${url}\"
        }")"
        assert_validate_refused
    done

    # Case 2 also passes the default, loopback, api_url on a co-located host.
    CURRENT_CASE='case 7: validate passes a loopback api_url on a co-located Kerbside host'
    validate_passes "$(write_vars loopback-colocated '{
      "kerbside_colocated": true, "api_url": "http://127.0.0.1:13000"
    }')"
}

case_8_url_mismatch() {
    CURRENT_CASE='case 8a: validate refuses a kerbside_url the Shaken Fist nodes see differently'
    validate_fails "Shaken Fist's nodes render a different kerbside_url, https://other.example.com/" \
        "$(write_vars url-differs '{"kerbside_url_on_sf_nodes": "https://other.example.com/"}')"
    assert_validate_refused

    # Byte for byte: a trailing slash is a different audience.
    validate_fails "Shaken Fist's nodes render a different kerbside_url" \
        "$(write_vars url-slash "{\"kerbside_url_on_sf_nodes\": \"${URL%/}\"}")"
    assert_validate_refused

    CURRENT_CASE='case 8b: validate refuses a kerbside_url the Shaken Fist nodes do not see'
    validate_fails "Shaken Fist's nodes render no kerbside_url at all" \
        "$(write_vars url-absent '{"kerbside_url_on_sf_nodes": ""}')"
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
parser = configparser.ConfigParser()
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
    grep -qF '%%25' "${CONF}/kerbside.ini" || fail "kerbside.ini does not double the SQL URL's %"
}

case_10_sources() {
    CURRENT_CASE='case 10: config renders a sources.yaml Kerbside can use'
    local out
    out="$("${PY}" - "${CONF}/sources.yaml" "${SF_CA_FILE}" "${SYSTEM_KEY}" << 'PYEOF' 2>&1
import sys

import yaml

path, ca_path, key = sys.argv[1:]
with open(path) as f:
    sources = yaml.safe_load(f)
with open(ca_path) as f:
    ca = f.read()
if not isinstance(sources, list) or len(sources) != 1:
    sys.exit(f'sources.yaml is not a list of one source: {sources!r}')
source = sources[0]
if source.get('ca_cert') != ca:
    sys.exit('ca_cert is not kerbside_sf_ca_cert byte for byte')
expected = {
    'source': 'sf',
    'type': 'shakenfist',
    'url': 'http://localhost:13000',
    'username': 'system',
}
for k, want in expected.items():
    if source.get(k) != want:
        sys.exit(f'{k} is {source.get(k)!r}, not {want!r}')
if source.get('password') != key:
    sys.exit('password is not kerbside_system_key')
PYEOF
)" || fail "${out}"
    [ "$(stat -c %a "${CONF}/sources.yaml")" = 640 ] \
        || fail "sources.yaml has mode $(stat -c %a "${CONF}/sources.yaml"), not 640"
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
    vars+=("$(write_vars api-url '{"api_url": "https://sf-api.example.com:13000"}')")
    desired_step 'api_url' "${CONF}/sources.yaml" : "${vars[@]}"
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
    refused sources.yaml 'sources.yaml refused: source 0 has no source' \
        "$(write_vars no-deploy-name '{"deploy_name": ""}')"
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

# bootstrap's virtualenv, a stub: its Python only answers bootstrap's
# site-packages question, its pip does nothing, and its uv installs nothing
# and freezes ${WORK}/freeze.txt, or fails to when ${WORK}/uv-freeze-fails
# exists. uv refuses to run without VIRTUAL_ENV set to the virtualenv, as the
# real one would then look elsewhere. bin/activate exists, so bootstrap does
# not create the virtualenv.
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
    'pip install') exit 0 ;;
    'pip freeze')
        if [ -f '${WORK}/uv-freeze-fails' ]; then
            echo 'uv stub: freeze failed' >&2
            exit 1
        fi
        cat '${WORK}/freeze.txt' ;;
    *) echo "uv stub: unexpected arguments: \$*" >&2; exit 2 ;;
esac
EOF
chmod +x "${BVENV}/bin/python" "${BVENV}/bin/pip" "${BVENV}/bin/uv"

# The installed code, as files whose contents a case can change.
install_stub_code() {
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
# outrank the fact bootstrap sets, and the stub virtualenv.
USER_NAME="$(id -un)" GROUP_NAME="$(id -gn)" STATE="${STATE}" BVENV="${BVENV}" \
    "${PY}" - "${WORK}/bootstrap-common.json" << 'PYEOF2'
import json
import os
import sys

env = os.environ
with open(sys.argv[1], 'w') as f:
    json.dump({
        'kerbside_state_dir': env['STATE'],
        'kerbside_venv': env['BVENV'],
        'kerbside_user': env['USER_NAME'],
        'kerbside_group': env['GROUP_NAME'],
        'kerbside_file_owner': env['USER_NAME'],
        'kerbside_file_group': env['GROUP_NAME'],
    }, f, indent=2)
PYEOF2

cat > "${WORK}/bootstrap.yml" << 'EOF'
---
- name: Run the kerbside role's bootstrap entry point
  hosts: localhost
  connection: local
  gather_facts: false
  tasks:
    - name: Bootstrap Kerbside
      ansible.builtin.include_role:
        name: shakenfist.kerbside.kerbside
        tasks_from: bootstrap

    - name: Report the code hash
      ansible.builtin.debug:
        msg: "CODE_HASH={{ kerbside_code_hash }}"
EOF

# run_bootstrap: bootstrap against the stub virtualenv, without its apt, user
# and group tasks. Returns its status, and leaves the hash in CODE_HASH.
run_bootstrap() {
    local rc=0
    ANSIBLE_SKIP_TAGS=packages,system-users COMMON_VARS="${WORK}/bootstrap-common.json" \
        run_ansible "${WORK}/bootstrap.yml" || rc=$?
    CODE_HASH="$(sed -n 's/.*"msg": "CODE_HASH=\([0-9a-f]\{64\}\)".*/\1/p' "${LAST_LOG}")"
    return "${rc}"
}

# code_hash_step DESCRIPTION same|new EDIT...: run the command EDIT, then
# bootstrap, and check that the code hash is the first one, or one not seen
# before.
SEEN_CODE_HASHES=()
code_hash_step() {
    local what="$1" expect="$2"
    shift 2
    CURRENT_CASE="case 14: bootstrap's code hash after ${what}"
    "$@"
    run_bootstrap || fail 'bootstrap failed'
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

case_14_bootstrap_code_hash() {
    CURRENT_CASE="case 14: bootstrap computes a code hash"
    install_stub_code
    run_bootstrap || fail 'bootstrap failed'
    [ -n "${CODE_HASH}" ] || fail 'bootstrap did not report a code hash'
    FIRST_CODE_HASH="${CODE_HASH}"
    SEEN_CODE_HASHES=("${CODE_HASH}")

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

    CURRENT_CASE="case 14: bootstrap fails when uv pip freeze fails"
    install_stub_code
    : > "${WORK}/uv-freeze-fails"
    if run_bootstrap; then
        fail 'bootstrap succeeded although uv pip freeze failed'
    fi
    rm -f "${WORK}/uv-freeze-fails"
    assert_output_has 'uv stub: freeze failed'
    [ -z "${CODE_HASH}" ] || fail 'bootstrap reported a code hash although uv pip freeze failed'

    CURRENT_CASE="case 14: bootstrap fails when a hashed package is missing"
    mv "${BSITE}/shakenfist_client" "${WORK}/shakenfist_client.moved"
    if run_bootstrap; then
        fail 'bootstrap succeeded although shakenfist_client is not installed'
    fi
    mv "${WORK}/shakenfist_client.moved" "${BSITE}/shakenfist_client"
    [ -z "${CODE_HASH}" ] || fail 'bootstrap reported a code hash although a package is missing'
}

case_15_secrets() {
    CURRENT_CASE='case 15: no secret reaches the ansible output'
    LAST_LOG=''
    # Prove the verbose runs happened, or their absence of secrets proves
    # nothing.
    grep -lq 'ESTABLISH LOCAL CONNECTION' "${WORK}"/logs/*.log \
        || fail 'no run was verbose'
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
case_7_loopback_api_url
case_8_url_mismatch
case_9_ini
case_10_sources
case_11_desired_state
case_12_refused_render
case_13_overrides
case_14_bootstrap_code_hash
case_15_secrets

echo "kerbside role: all fifteen cases passed (${RUNS} ansible runs, $((SECONDS - START))s)"
