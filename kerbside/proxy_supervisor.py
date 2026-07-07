"""Launch and supervise the Rust kerbside-proxy as a child process.

Phase 5: when PROXY_IMPLEMENTATION is "rust", the daemon runs the Rust proxy
binary as a supervised child instead of forking the in-process Python proxy.
This module locates the binary, builds its argv from config (the flags mirror
the proxy's clap CLI in rust/kerbside-proxy/src/main.rs), launches it, and
terminates it with a SIGTERM-then-SIGKILL deadline. The firewall knobs are NOT
passed as flags -- they are delivered per connection over gRPC.
"""

import os
import shutil
import subprocess
from pathlib import Path

from shakenfist_utilities import logs

from kerbside import util


LOG, _ = logs.setup(__name__, **util.configure_logging())

# Env override for the binary path, and the binary's installed name (on PATH
# once the maturin wheel from phase 6 is installed).
PROXY_BIN_ENV = 'KERBSIDE_PROXY_BIN'
PROXY_BIN_NAME = 'kerbside-proxy'


def find_proxy_bin():
    """Locate the kerbside-proxy binary.

    Resolution order: the KERBSIDE_PROXY_BIN env override, then kerbside-proxy
    on PATH (the installed-wheel case, phase 6), then the in-repo dev build
    dirs (release before debug). Raises RuntimeError naming every searched
    location if none is a usable executable, so a misconfiguration fails fast
    and loud rather than silently.
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
