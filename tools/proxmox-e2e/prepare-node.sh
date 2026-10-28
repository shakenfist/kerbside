#!/bin/bash
#
# Prepare the Proxmox lane's PVE node for kerbside: create kerbside's API
# token the way docs/console-sources.md says to, two more tokens that each
# lack one of its privileges, and guests that discovery must skip.
#
# Usage:
#   prepare-node.sh --node-address ADDRESS --vmid VMID --workdir DIR \
#       [--ssh-user debian] [--ssh-key /srv/github/id_ci]
#
# ADDRESS is deploy-proxmox-on-shakenfist's node_address output and VMID its
# vmid output, the SPICE smoke guest. Runs on the runner, after that action,
# in the same job.
#
# HOW THE RUNNER REACHES THE NODE. The action's playbook boots the node from
# the debian:13 image with the CI mesh's key, /srv/github/id_ci.pub, adds the
# runner to the node's network, and logs in as debian with
# /srv/github/id_ci, using sudo for everything. This does the same, to
# node_address: the node's address on that network, which the runner
# reaches directly. The node is new on every run, so its host key is not
# checked.
#
# WHAT IT DOES, in order:
#
#   1. Runs the shell block under "### Proxmox VE account" in
#      docs/console-sources.md on the node, as root, as
#      tools/proxmox-e2e/account_commands.py extracts it: with the user
#      renamed kerbside-lane@pve, and refused unless every command in it is
#      one of the four pveum commands the account needs.
#   2. Creates two more privilege-separated tokens for the same user, one
#      with a role holding only VM.Audit (audit-only) and one with a role
#      holding only VM.Console (console-only). The user holds both
#      privileges, from step 1, so each token differs from the documented
#      one by exactly one privilege. tools/proxmox-e2e/check-privileges.py
#      shows that each is refused what the missing privilege allows.
#   3. Checks that the three tokens' effective privileges on the smoke
#      guest are exactly the expected ones. Without this, a token whose ACL
#      was never applied would hold nothing, and be refused everything:
#      that would pass check-privileges.py while proving nothing. It also
#      checks every path each token holds privileges on, so that a
#      documented ACL granting more elsewhere (on /, say, or /nodes) fails
#      the lane: each such path must be /vms or under it, and hold none but
#      the expected privileges.
#   4. Creates diskless 64 MB guests, which never boot an OS, for the
#      discovery rules to skip:
#        101  running, with the default std display (no SPICE server);
#        102  running, qxl, with its SMBIOS UUID deleted;
#        103  stopped, qxl;
#        104  a qxl template, when qm template accepts a diskless guest.
#      It then waits until the cluster's resource list reports each in that
#      state, so that kerbside's first scrape skips each for the reason it
#      was made for, rather than because its status was not yet reported.
#   5. Writes DIR/lane-node.json: each token's ID and secret file, and the
#      guests made. None of it is secret. Under GitHub Actions the documented
#      token's ID and file, and that JSON file's path, are also step outputs
#      (token_id, token_file and lane_file).
#
# WHAT ONLY THE LANE EXERCISES. These were written from PVE's documented
# behaviour and source, and are first checked by the lane on a real node:
#
#   - the JSON "pveum user token permissions" prints, with --path (one
#     path, each privilege a key) and without it (every path the token
#     holds privileges on, and none it holds nothing on);
#   - whether "qm template" accepts a diskless guest (step 4 copes with
#     either answer).
#
# It is not idempotent. The node is discarded with the runner's namespace,
# and a second run fails at the first "pveum role add".
#
# THE SECRETS. Each token's secret goes from the JSON "pveum user token add"
# prints, over ssh, through jq, straight into a 0600 file in DIR: it is never
# in a shell variable that is printed, on a command line, or in the log.
# Under GitHub Actions it is then masked, before anything else reads that
# file. xtrace is turned off regardless, in case it was inherited: under
# xtrace the mask line itself would print the secret. Do not add set -x, and
# print token IDs and file paths only.

set +o xtrace
set -o errexit
set -o nounset
set -o pipefail

fail() {
    echo "::error title=Proxmox lane::$*"
    echo "prepare-node.sh: $*" >&2
    exit 1
}

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

node_address=''
vmid=''
workdir=''
ssh_user='debian'
ssh_key='/srv/github/id_ci'

while [ "$#" -gt 0 ]; do
    case "$1" in
        --node-address|--vmid|--workdir|--ssh-user|--ssh-key)
            [ "$#" -ge 2 ] || fail "$1 needs a value"
            case "$1" in
                --node-address) node_address="$2" ;;
                --vmid) vmid="$2" ;;
                --workdir) workdir="$2" ;;
                --ssh-user) ssh_user="$2" ;;
                --ssh-key) ssh_key="$2" ;;
            esac
            shift 2
            ;;
        *)
            fail "unknown argument: $1"
            ;;
    esac
done

for required in node_address vmid workdir; do
    [ -n "${!required}" ] || fail "--${required//_/-} is required"
done
# These end up in commands run on the node as root.
[[ "${node_address}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || fail "--node-address is not an IPv4 address: ${node_address}"
[[ "${vmid}" =~ ^[0-9]+$ ]] || fail "--vmid is not a number: ${vmid}"
[[ "${ssh_user}" =~ ^[a-z_][a-z0-9_-]*$ ]] || fail "--ssh-user is not a user name: ${ssh_user}"
[[ "${workdir}" = /* ]] || fail "--workdir must be an absolute path: ${workdir}"

# Every file made from here on is the runner user's alone.
umask 077
mkdir -p "${workdir}"
chmod 0700 "${workdir}"

ssh_opts=(-i "${ssh_key}" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
          -o BatchMode=yes -o ConnectTimeout=10 -o LogLevel=ERROR)

# Run one command line on the node. ssh hands the remote shell a single
# string, so callers pass one, quoted as that shell should read it.
# stdin is closed, because ssh would otherwise read the rest of whatever
# loop it is called from.
node() {
    timeout 120 ssh "${ssh_opts[@]}" "${ssh_user}@${node_address}" "$1" < /dev/null
}

# Run a "pveum user token add ... --output-format json" command line on the
# node and keep only the secret, in FILE. The jq filter checks the output
# names the token expected; its error names the token, never the value.
create_token() {
    local command="$1" token_id="$2" file="$3"

    rm -f "${file}"
    node "sudo -n ${command}" \
        | jq -j --arg id "${token_id}" \
            'if .["full-tokenid"] == $id and (.value | type) == "string" and (.value | test("^\\S+$"))
             then .value else error("the output does not hold a secret for " + $id) end' \
            > "${file}" \
        || fail "could not create the token ${token_id} (the reason is above)"
    [ -s "${file}" ] || fail "no secret was written for the token ${token_id}"

    # Masked from the file, with builtins only, so the value is on no
    # command line. Outside GitHub Actions there is no runner to read the
    # mask line, and printing it would print the secret.
    if [ "${GITHUB_ACTIONS:-}" = 'true' ]; then
        local secret
        secret="$(< "${file}")"
        echo "::add-mask::${secret}"
        unset secret
    fi
    echo "Created the token ${token_id}; its secret is in ${file}"
}

# Fail if TOKEN_ID's effective privileges on the smoke guest are not exactly
# the space separated, sorted PRIVILEGES.
check_privileges() {
    local token_id="$1" privileges="$2" granted

    granted="$(node "sudo -n pveum user token permissions '${token_id%%!*}' '${token_id#*!}' --path /vms/${vmid} --output-format json")" \
        || fail "could not read the privileges of ${token_id}"
    jq -e --arg want "${privileges}" \
        'to_entries | length == 1 and ((.[0].value | keys) == ($want | split(" ")))' \
        <<< "${granted}" > /dev/null \
        || fail "${token_id} should hold exactly ${privileges} on /vms/${vmid}, but PVE says: ${granted}"
    echo "${token_id} holds exactly ${privileges} on /vms/${vmid}"

    # With no --path, PVE lists every path the token holds a privilege on.
    granted="$(node "sudo -n pveum user token permissions '${token_id%%!*}' '${token_id#*!}' --output-format json")" \
        || fail "could not read the privileges of ${token_id} on every path"
    # Paths and privilege names only, one path to a line.
    held="$(jq -r 'to_entries[] | "\(.key): \(.value | keys | join(" "))"' <<< "${granted}")" \
        || fail "PVE's list of ${token_id}'s privileges on every path is not a JSON object of paths"
    jq -e --arg want "${privileges}" \
        '($want | split(" ")) as $want
         | type == "object"
           and all(to_entries[]; (.value | type) == "object"
                                 and (((.key == "/vms" or (.key | startswith("/vms/")))
                                       and ((.value | keys) - $want | length) == 0)
                                      or (.value | length) == 0))' \
        <<< "${granted}" > /dev/null \
        || { echo "${held}" >&2
             fail "${token_id} should hold nothing outside /vms, and nothing but ${privileges} within it (it holds the above)"; }
    echo "${token_id} holds nothing outside /vms, and nothing but ${privileges} within it:"
    echo "${held}"
}

node 'sudo -n true' \
    || fail "cannot run commands as root on ${ssh_user}@${node_address}"

# 1. The documented account. Read whole, before anything runs, so that a
# refused block runs none of its commands.
commands="$(python3 "${here}/account_commands.py")" \
    || fail 'refusing to run the documented account commands (the reason is above)'
documented_id="$(python3 "${here}/account_commands.py" --token-id)"
# account_commands.py refuses any other form, but the ID is built into root
# commands and a file path below, so it is checked again here.
token_id_form='^[A-Za-z0-9._-]+@[A-Za-z0-9._-]+![A-Za-z0-9._-]+$'
[[ "${documented_id}" =~ ${token_id_form} ]] \
    || fail "the documented token ID is not of the form user@realm!tokenid: ${documented_id}"
user="${documented_id%%!*}"
documented_file="${workdir}/token-${documented_id#*!}"

echo "Creating the account docs/console-sources.md documents, as ${user}"
while IFS= read -r command; do
    case "${command}" in
        'pveum user token add '*)
            echo "On the node: ${command}"
            create_token "${command}" "${documented_id}" "${documented_file}"
            ;;
        *)
            echo "On the node: ${command}"
            node "sudo -n ${command}" || fail "the documented command failed: ${command}"
            ;;
    esac
done <<< "${commands}"
[ -s "${documented_file}" ] || fail "the documented commands did not create ${documented_id}"

# 2. The single-privilege tokens.
audit_id="${user}!audit-only"
audit_file="${workdir}/token-audit-only"
console_id="${user}!console-only"
console_file="${workdir}/token-console-only"

node "sudo -n pveum role add KerbsideAuditOnly --privs VM.Audit" || fail 'could not create the role KerbsideAuditOnly'
create_token "pveum user token add '${user}' audit-only --privsep 1 --output-format json" \
    "${audit_id}" "${audit_file}"
node "sudo -n pveum acl modify /vms --roles KerbsideAuditOnly --tokens '${audit_id}'" \
    || fail "could not give ${audit_id} its role"

node "sudo -n pveum role add KerbsideConsoleOnly --privs VM.Console" || fail 'could not create the role KerbsideConsoleOnly'
create_token "pveum user token add '${user}' console-only --privsep 1 --output-format json" \
    "${console_id}" "${console_file}"
node "sudo -n pveum acl modify /vms --roles KerbsideConsoleOnly --tokens '${console_id}'" \
    || fail "could not give ${console_id} its role"

# 3. What each token can really do.
check_privileges "${documented_id}" 'VM.Audit VM.Console'
check_privileges "${audit_id}" 'VM.Audit'
check_privileges "${console_id}" 'VM.Console'

# 4. Guests discovery must skip. The node may have no /dev/kvm, as the
# action's smoke guest allows for, and a kvm=1 guest would then not start.
kvm="$(node 'if test -e /dev/kvm; then echo 1; else echo 0; fi')" \
    || fail 'could not tell whether the node has /dev/kvm'
[[ "${kvm}" =~ ^[01]$ ]] || fail "the node's answer to whether it has /dev/kvm was not 0 or 1: ${kvm}"

# Diskless and without a NIC, so it never boots anything: its firmware
# finds no boot device and waits, which is all a skipped guest needs to do.
create_guest() {
    local guest="$1" name="$2"
    shift 2
    node "sudo -n qm create ${guest} --name ${name} --memory 64 --kvm ${kvm} $*" \
        || fail "could not create guest ${guest}"
}

create_guest 101 kerbside-skip-std-vga
node 'sudo -n qm start 101' || fail 'could not start guest 101'

create_guest 102 kerbside-skip-no-smbios --vga qxl
node 'sudo -n qm set 102 --delete smbios1' || fail 'could not delete the SMBIOS UUID of guest 102'
node 'sudo -n qm start 102' || fail 'could not start guest 102'

create_guest 103 kerbside-skip-stopped --vga qxl

create_guest 104 kerbside-skip-template --vga qxl
if node 'sudo -n qm template 104'; then
    template=true
else
    echo '::notice title=Proxmox lane::qm template refused a diskless guest, so there is no template to skip'
    node 'sudo -n qm destroy 104' || fail 'could not remove guest 104'
    template=false
fi

# Each fixture is what it claims to be: a vga line would mean 101 is not on
# the std default, and an smbios1 line that 102 still has its UUID. Read
# whole rather than piped to grep -q, whose early exit would fail the
# pipeline.
config="$(node 'sudo -n qm config 101')" || fail 'could not read the configuration of guest 101'
! grep -q '^vga:' <<< "${config}" || fail 'guest 101 has a display set, not the std default'
config="$(node 'sudo -n qm config 102')" || fail 'could not read the configuration of guest 102'
! grep -q '^smbios1:' <<< "${config}" || fail 'guest 102 still has an SMBIOS UUID'

echo 'Waiting for the cluster resource list to report the guests'
reported=false
for _ in $(seq 1 30); do
    if node 'sudo -n pvesh get /cluster/resources --type vm --output-format json' \
            | jq -e --argjson smoke "${vmid}" --argjson template "${template}" \
                'def guest($id): map(select(.vmid == $id)) | first;
                 (guest($smoke).status == "running")
                 and (guest(101).status == "running")
                 and (guest(102).status == "running")
                 and (guest(103).status == "stopped")
                 and (if $template then guest(104).template == 1 else guest(104) == null end)' \
                > /dev/null; then
        reported=true
        break
    fi
    sleep 5
done
[ "${reported}" = true ] || fail 'the cluster resource list never reported the guests in the states they were made in'
node 'sudo -n qm list' || fail 'could not list the guests'

# 5. What the later steps need.
lane_file="${workdir}/lane-node.json"
jq -n \
    --arg documented_id "${documented_id}" --arg documented_file "${documented_file}" \
    --arg audit_id "${audit_id}" --arg audit_file "${audit_file}" \
    --arg console_id "${console_id}" --arg console_file "${console_file}" \
    --argjson template "${template}" \
    '{tokens: {documented: {token_id: $documented_id, secret_file: $documented_file},
               audit_only: {token_id: $audit_id, secret_file: $audit_file},
               console_only: {token_id: $console_id, secret_file: $console_file}},
      skipped_guests: {std_display: 101, no_smbios_uuid: 102, stopped: 103,
                       template: (if $template then 104 else null end)}}' \
    > "${lane_file}"
echo "Wrote ${lane_file}"

if [ -n "${GITHUB_OUTPUT:-}" ]; then
    {
        echo "token_id=${documented_id}"
        echo "token_file=${documented_file}"
        echo "lane_file=${lane_file}"
    } >> "${GITHUB_OUTPUT}"
fi
