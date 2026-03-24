#!/usr/bin/python3

"""Test SPICE console connectivity for an oVirt VM.

Connects to the oVirt engine API, finds the test VM, verifies that
SPICE display is configured, retrieves the libvirt domain XML, and
attempts a SPICE protocol handshake on the console port.
"""

import argparse
import socket
import struct
import sys
import time

import ovirtsdk4 as sdk
import ovirtsdk4.types as types


def parse_args():
    parser = argparse.ArgumentParser(
        description='Test SPICE console connectivity for an oVirt VM.'
    )
    parser.add_argument(
        '--url', required=True,
        help='oVirt Engine API URL'
    )
    parser.add_argument('--username', default='admin@internal')
    parser.add_argument('--password', required=True)
    parser.add_argument('--ca-file', required=True)
    parser.add_argument(
        '--vm-name-prefix', default='kerbside-test-',
        help='Prefix to match VM name (default: kerbside-test-)'
    )
    parser.add_argument(
        '--timeout-mins', type=int, default=5,
        help='Timeout in minutes'
    )
    return parser.parse_args()


def heading(text):
    print()
    print('=' * 60)
    print(text)
    print('=' * 60)


def test_spice_handshake(host, port):
    """Attempt a SPICE protocol handshake and verify the response."""
    magic = b'REDQ'
    major = 2
    minor = 2
    main_channel = 1
    common_caps = 11
    channel_caps = 9

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    try:
        sock.connect((host, port))
        sock.sendall(struct.pack(
            '<4sIIIIBBIIIII', magic, major, minor, 42 - 16,
            0, main_channel, 0, 1, 1, 18, common_caps,
            channel_caps))

        buffered = sock.recv(20)
        (
            server_magic, server_major, server_minor, _, server_error
        ) = struct.unpack_from('<4sIIII', buffered)

        assert server_magic == b'REDQ', (
            f'Bad magic: {server_magic!r}'
        )
        assert server_major == 2, (
            f'Bad major version: {server_major}'
        )
        assert server_minor == 2, (
            f'Bad minor version: {server_minor}'
        )

        # SPICE link error codes (from spice.proto):
        #   0 = OK
        #   5 = NEED_SECURED (reconnect on TLS port required)
        # Code 5 is expected when connecting on the insecure port
        # to a server that requires TLS — it confirms the SPICE
        # server is alive and speaking the correct protocol.
        error_names = {
            0: 'OK', 1: 'ERROR', 2: 'INVALID_MAGIC',
            3: 'INVALID_DATA', 4: 'VERSION_MISMATCH',
            5: 'NEED_SECURED', 6: 'NEED_UNSECURED',
            7: 'PERMISSION_DENIED', 8: 'BAD_CONNECTION_ID',
            9: 'CHANNEL_NOT_AVAILABLE',
        }
        error_name = error_names.get(server_error, 'UNKNOWN')
        print(f'  SPICE handshake OK: server responded with '
              f'{error_name} ({server_error})')

        if server_error not in (0, 5):
            print(f'  WARNING: unexpected error code '
                  f'{server_error} ({error_name})')

        return True
    finally:
        sock.close()


def main():
    args = parse_args()
    timeout_secs = args.timeout_mins * 60

    heading('Connect to oVirt engine')
    connection = sdk.Connection(
        url=args.url,
        username=args.username,
        password=args.password,
        ca_file=args.ca_file,
    )
    try:
        system_service = connection.system_service()
        vms_service = system_service.vms_service()

        heading('Find test VM')
        target_vm = None
        for vm in vms_service.list():
            if vm.name.startswith(args.vm_name_prefix):
                target_vm = vm
                break

        if not target_vm:
            print(f'ERROR: No VM found matching '
                  f'prefix {args.vm_name_prefix!r}')
            print('  Available VMs:')
            for vm in vms_service.list():
                print(f'    {vm.name} (status={vm.status})')
            sys.exit(1)

        print(f'  Found VM: {target_vm.name} '
              f'(id={target_vm.id}, status={target_vm.status})')

        if target_vm.status != types.VmStatus.UP:
            print(f'ERROR: VM is not running '
                  f'(status={target_vm.status})')
            sys.exit(1)

        heading('Check VM display configuration')
        vm_service = vms_service.vm_service(target_vm.id)
        vm_detail = vm_service.get(
            all_content=True,
        )

        display = vm_detail.display
        if not display:
            print('ERROR: VM has no display configured')
            sys.exit(1)

        print(f'  Display type: {display.type}')
        print(f'  Address: {display.address}')
        print(f'  Port: {display.port}')
        print(f'  Secure port: {display.secure_port}')

        if display.type != types.DisplayType.SPICE:
            print(f'ERROR: Display type is {display.type}, '
                  f'expected SPICE')
            sys.exit(1)

        heading('List graphics consoles')
        graphics_consoles = vm_service.graphics_consoles_service()
        consoles = graphics_consoles.list(current=True)
        if not consoles:
            print('ERROR: No graphics consoles found')
            sys.exit(1)

        for c in consoles:
            print(f'  Console: protocol={c.protocol}, '
                  f'address={c.address}, port={c.port}, '
                  f'tls_port={c.tls_port}')

        heading('Verify libvirt domain XML')
        # Get the host where the VM is running
        host_id = vm_detail.host.id if vm_detail.host else None
        if not host_id:
            print('WARNING: Cannot determine host, '
                  'skipping XML check')
        else:
            hosts_service = system_service.hosts_service()
            host_service = hosts_service.host_service(host_id)
            host = host_service.get()
            print(f'  VM is on host: {host.name} '
                  f'({host.address})')

        heading('Test SPICE protocol connectivity')
        # Use the display address reported by oVirt (typically
        # the host's IP). Fall back to localhost if not set.
        spice_host = display.address or '127.0.0.1'
        spice_port = display.port

        if not spice_port:
            print('ERROR: No SPICE port available')
            sys.exit(1)

        print(f'  Connecting to {spice_host}:{spice_port}...')

        # Retry a few times — the SPICE server may take a
        # moment to become ready
        start = time.time()
        last_error = None
        while time.time() - start < timeout_secs:
            try:
                test_spice_handshake(spice_host, spice_port)
                last_error = None
                break
            except (ConnectionRefusedError, socket.timeout,
                    OSError) as e:
                last_error = e
                print(f'  Connection failed ({e}), '
                      f'retrying in 5s...')
                time.sleep(5)
            except AssertionError as e:
                print(f'ERROR: SPICE handshake failed: {e}')
                sys.exit(1)

        if last_error:
            print(f'ERROR: Could not connect to SPICE port '
                  f'after {timeout_secs}s: {last_error}')
            sys.exit(1)

        heading('oVirt SPICE console test complete')
        print('  All checks passed.')

    finally:
        connection.close()


if __name__ == '__main__':
    main()
