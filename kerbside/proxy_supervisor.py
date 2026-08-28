"""Launch and supervise the Rust kerbside-proxy as a child process.

The daemon runs the Rust proxy binary as a supervised child. This module
locates the binary, verifies that it speaks the same gRPC contract as this
Python package (the contract handshake -- a sha256 of kerbside.proto embedded
in both sides, compared before launch), builds its argv from config (the flags
mirror the proxy's clap CLI in rust/kerbside-proxy/src/main.rs), launches it,
and terminates it with a SIGTERM-then-SIGKILL deadline. The firewall knobs are
NOT passed as flags -- they are delivered per connection over gRPC.
"""

import os
import re
import shutil
import subprocess
from pathlib import Path

from shakenfist_utilities import logs

from kerbside import util
from kerbside.rpc.contract import CONTRACT_HASH


LOG, _ = logs.setup(__name__, **util.configure_logging())

# Env override for the binary path, and the binary's installed name (on
# PATH once the maturin wheel is installed).
PROXY_BIN_ENV = 'KERBSIDE_PROXY_BIN'
PROXY_BIN_NAME = 'kerbside-proxy'

# Env escape hatch which bypasses the contract handshake below. For debugging
# only: it lets an operator who knows better launch a binary whose gRPC
# contract this package cannot confirm matches its own. Skips only for a
# recognised truthy value (case-insensitively): '1', 'true', 'yes', 'on'.
SKIP_CONTRACT_CHECK_ENV = 'KERBSIDE_SKIP_CONTRACT_CHECK'
_SKIP_CONTRACT_CHECK_TRUE_VALUES = ('1', 'true', 'yes', 'on')
_SKIP_CONTRACT_CHECK_FALSE_VALUES = ('0', 'false', 'no', 'off')

# A contract hash is a sha256 hex digest, lower case.
CONTRACT_HASH_RE = re.compile(r'^[0-9a-f]{64}$')

# How long to wait for `<bin_path> --contract-hash` before giving up.
CONTRACT_HASH_PROBE_TIMEOUT = 10


def find_proxy_bin():
    """Locate the kerbside-proxy binary.

    Resolution order: the KERBSIDE_PROXY_BIN env override, then
    kerbside-proxy on PATH (the installed-wheel case), then the in-repo dev
    build dirs (release before debug). Raises RuntimeError naming every
    searched location if none is a usable executable, so a misconfiguration
    fails fast and loud rather than silently.
    """
    searched = []

    # An explicit override is authoritative: if it is set but not a usable
    # executable, fail rather than silently falling through to a different
    # binary on PATH or in the build tree (which would launch something the
    # operator did not intend).
    env = os.environ.get(PROXY_BIN_ENV)
    if env:
        if os.path.isfile(env) and os.access(env, os.X_OK):
            return env
        raise RuntimeError(
            '%s is set to %r, which is not an executable file.' % (PROXY_BIN_ENV, env))

    on_path = shutil.which(PROXY_BIN_NAME)
    if on_path:
        return on_path
    searched.append('%s on PATH' % PROXY_BIN_NAME)

    repo_root = Path(__file__).resolve().parents[1]
    for profile in ('release', 'debug'):
        candidate = repo_root / 'rust' / 'kerbside-proxy' / 'target' / profile / PROXY_BIN_NAME
        searched.append(str(candidate))
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)

    raise RuntimeError(
        'Could not find the %s binary (searched: %s). Set %s to its path or '
        'build it with `make -C rust/kerbside-proxy build`.' % (
            PROXY_BIN_NAME, ', '.join(searched), PROXY_BIN_ENV))


def get_binary_contract_hash(bin_path):
    """Ask the proxy binary for its embedded gRPC contract hash.

    Runs `<bin_path> --contract-hash`, which prints the sha256 of the
    kerbside.proto the binary was compiled against and exits zero.

    Returns a (reported_hash, failure_reason) tuple where exactly one
    element is not None: reported_hash on success, or else failure_reason,
    a short human-readable string describing why the hash could not be
    determined -- a non-zero exit (every release <= 0.4.0 predates the flag
    and so rejects it), a timeout, output which is not a 64 character lower
    case hex digest (including output which is not even valid UTF-8), or an
    OSError raised trying to execute the binary at all (wrong architecture,
    missing permissions, missing file).

    check_contract() treats every failure_reason as a mismatch, because none
    of them can be shown to speak this package's contract.
    """
    try:
        # errors='replace' rather than the strict default: a binary which
        # prints something which is not UTF-8 must produce a failure reason
        # like every other bad answer does, not a UnicodeDecodeError escaping
        # this function and surfacing as a traceback at daemon startup. The
        # mangled text then fails the digest check below on its own.
        result = subprocess.run(
            [bin_path, '--contract-hash'], capture_output=True, text=True,
            errors='replace', timeout=CONTRACT_HASH_PROBE_TIMEOUT)
    except subprocess.TimeoutExpired:
        LOG.warning('%s --contract-hash timed out' % bin_path)
        return None, (
            'the binary did not respond to --contract-hash within %ds'
            % CONTRACT_HASH_PROBE_TIMEOUT)
    except OSError as e:
        LOG.warning('%s --contract-hash could not be executed: %s' % (bin_path, e))
        return None, 'the binary could not be executed: %s' % e

    if result.returncode != 0:
        LOG.warning(
            '%s --contract-hash exited %d' % (bin_path, result.returncode))
        return None, 'the binary does not support --contract-hash; it predates the contract handshake'

    reported = result.stdout.strip()
    if not CONTRACT_HASH_RE.match(reported):
        trimmed = reported[:80]
        LOG.warning('%s --contract-hash printed unexpected output: %r' % (bin_path, trimmed))
        return None, 'the binary printed %r, which is not a sha256 digest' % trimmed
    return reported, None


def check_contract(bin_path):
    """Refuse to launch a proxy binary which disagrees about the gRPC contract.

    Both sides embed the sha256 of kerbside/rpc/kerbside.proto: this package
    as a generated constant, the binary at compile time. If they differ (or
    the binary cannot tell us its hash at all) the pairing is skewed, so we
    raise rather than launch something which would fail subtly at connection
    time instead.
    """
    reported, failure_reason = get_binary_contract_hash(bin_path)
    if reported == CONTRACT_HASH:
        LOG.info('Proxy binary contract hash matches: %s' % CONTRACT_HASH)
        return

    if reported is None:
        found = 'unknown (%s)' % failure_reason
    else:
        found = reported

    raise RuntimeError(
        'The %s binary at %s does not match this kerbside version\'s gRPC contract.\n'
        'Expected contract hash: %s\n'
        'Binary contract hash:   %s\n'
        'Fix this by one of: upgrading the kerbside-proxy wheel to one matching this '
        'kerbside version; rebuilding the local Rust tree with '
        '`make -C rust/kerbside-proxy build`; pointing %s at a matching binary; or '
        'setting %s=1 to bypass this check for debugging.' % (
            PROXY_BIN_NAME, bin_path, CONTRACT_HASH, found, PROXY_BIN_ENV,
            SKIP_CONTRACT_CHECK_ENV))


def build_proxy_argv(bin_path, cfg):
    """Build the Rust proxy argv from config. Flags mirror main.rs's clap Args.

    The firewall knobs (FIREWALL_MODE / FIREWALL_PERMITTED_CHANNELS) are NOT
    included: they are delivered per connection in the AuthorizeConnection
    reply, not on the command line.
    """
    argv = [
        bin_path,
        '--vdi-address', cfg.VDI_ADDRESS,
        '--secure-port', str(cfg.VDI_SECURE_PORT),
        '--insecure-port', str(cfg.VDI_INSECURE_PORT),
        '--cert', cfg.PROXY_HOST_CERT_PATH,
        '--cert-key', cfg.PROXY_HOST_CERT_KEY_PATH,
        '--cacert', cfg.CACERT_PATH,
        '--host-subject', cfg.PROXY_HOST_SUBJECT,
        '--node-name', cfg.NODE_NAME,
        '--prometheus-port', str(cfg.PROMETHEUS_METRICS_PORT),
        '--metrics-address', cfg.PROMETHEUS_METRICS_ADDRESS,
        '--api-socket', cfg.API_SOCKET_PATH,
    ]
    if cfg.LOG_VERBOSE:
        argv.append('--verbose')
    return argv


def launch_rust_proxy(cfg):
    """Launch the Rust proxy as a child, inheriting stdout/stderr so its
    tracing output lands in the daemon's log stream. Returns the Popen."""
    bin_path = find_proxy_bin()

    # The escape hatch only takes effect for a recognised truthy value
    # ('1', 'true', 'yes', 'on', case-insensitively). An unset or empty
    # variable, or an explicit falsy value ('0', 'false', 'no', 'off'),
    # keeps the check; anything else is not recognised, so the check is
    # kept and a warning names the unrecognised value.
    skip_raw = os.environ.get(SKIP_CONTRACT_CHECK_ENV, '')
    skip_value = skip_raw.strip().lower()
    if skip_value in _SKIP_CONTRACT_CHECK_TRUE_VALUES:
        # Still probe the binary so the operator gets data to debug with,
        # even though a mismatch (or probe failure) will not block launch.
        reported, failure_reason = get_binary_contract_hash(bin_path)
        found = reported if reported is not None else 'unknown (%s)' % failure_reason
        LOG.warning(
            'SKIPPING the proxy contract check by operator request (%s=%s). Expected '
            'contract hash: %s. Binary contract hash: %s. The proxy binary at %s may '
            'not speak this kerbside version\'s gRPC contract.'
            % (SKIP_CONTRACT_CHECK_ENV, skip_raw, CONTRACT_HASH, found, bin_path))
    else:
        if skip_raw != '' and skip_value not in _SKIP_CONTRACT_CHECK_FALSE_VALUES:
            LOG.warning(
                '%s=%r is not a recognised value; keeping the contract check. Set it to '
                "one of '1', 'true', 'yes', 'on' to skip." % (SKIP_CONTRACT_CHECK_ENV, skip_raw))
        check_contract(bin_path)

    argv = build_proxy_argv(bin_path, cfg)
    # argv carries only paths and ports, no secrets, so it is safe to log.
    LOG.info('Launching Rust proxy child: %s' % ' '.join(argv))
    return subprocess.Popen(argv, close_fds=True)


def terminate_child(proc, deadline_seconds):
    """Stop the child: SIGTERM, wait up to deadline_seconds for a graceful
    exit (the proxy drains in-flight sessions), then SIGKILL if it overruns."""
    if proc.poll() is not None:
        return
    LOG.info('Sending SIGTERM to Rust proxy child (pid %s)' % proc.pid)
    proc.terminate()
    try:
        proc.wait(timeout=deadline_seconds)
        LOG.info('Rust proxy child exited cleanly after SIGTERM')
    except subprocess.TimeoutExpired:
        LOG.warning(
            'Rust proxy child did not exit within %ss; sending SIGKILL'
            % deadline_seconds)
        proc.kill()
        proc.wait()
