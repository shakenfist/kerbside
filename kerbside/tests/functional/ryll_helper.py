"""Assert SPICE connectivity via ryll (the Rust SPICE client).

The Python SpiceClient was removed at the Rust-proxy cutover (phase 8). These
live-cloud functional tests now assert "a SPICE console is reachable" by
driving ryll headless against a .vv and confirming it establishes a session --
its control socket appears and it stays up -- which is the ryll equivalent of
the old SpiceClient.connect() not raising. ryll must be on PATH.

These are live-cloud tests (not part of the unit gate); the ryll port is
verified by inspection here and exercised on the operator's cloud / the
functional lane.
"""

import os
import shutil
import subprocess
import tempfile
import time


class RyllNotAvailable(Exception):
    pass


class SpiceConnectFailed(Exception):
    pass


def vv_from_static(host, port, tls_port=None, password=''):
    """Build a minimal virt-viewer .vv for a direct (proxy-less) connection."""
    lines = ['[virt-viewer]', 'type=spice', 'host=%s' % host]
    if port:
        lines.append('port=%s' % port)
    if tls_port:
        lines.append('tls-port=%s' % tls_port)
    lines.append('password=%s' % password)
    return '\n'.join(lines) + '\n'


def assert_spice_connects(vv_text, timeout=60, settle=2):
    """Assert ryll can connect to the SPICE console described by vv_text.

    Writes the .vv content to a temp file, launches
    `ryll --headless --file <vv> --control-socket <sock>`, and waits up to
    `timeout` seconds for the control socket to appear. ryll creates it once
    its event loop is running against an established session, so its
    appearance -- confirmed stable for `settle` seconds, since ryll unlinks it
    and exits if the connection then drops -- is the connectivity oracle.
    Raises SpiceConnectFailed on failure; always cleans up ryll and temp files.
    """
    ryll = shutil.which('ryll')
    if not ryll:
        raise RyllNotAvailable('ryll not found on PATH')

    workdir = tempfile.mkdtemp(prefix='kerbside-ryll-')
    vv_path = os.path.join(workdir, 'console.vv')
    sock_path = os.path.join(workdir, 'ryll.sock')
    with open(vv_path, 'w') as f:
        f.write(vv_text)

    proc = subprocess.Popen(
        [ryll, '--headless', '--file', vv_path, '--control-socket', sock_path],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    def _dump():
        try:
            return proc.stdout.read().decode('utf-8', 'replace') if proc.stdout else ''
        except Exception:
            return ''

    try:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if os.path.exists(sock_path):
                # Guard against a socket that appears then tears down when the
                # connection fails: confirm ryll is still alive after a settle.
                time.sleep(settle)
                if proc.poll() is not None:
                    raise SpiceConnectFailed(
                        'ryll exited (rc=%s) right after connecting:\n%s'
                        % (proc.returncode, _dump()))
                return
            if proc.poll() is not None:
                raise SpiceConnectFailed(
                    'ryll exited (rc=%s) before establishing a session:\n%s'
                    % (proc.returncode, _dump()))
            time.sleep(0.5)
        raise SpiceConnectFailed(
            'ryll did not establish a SPICE session within %ss' % timeout)
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        shutil.rmtree(workdir, ignore_errors=True)
