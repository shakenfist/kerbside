#!/usr/bin/python3

"""Create an oVirt VM suitable as a SPICE test target for kerbside.

This script sets up oVirt infrastructure (datacenter, cluster, hypervisor
host, local storage domain) then uploads a desktop QCOW2 image, creates
a template from it, and starts a VM. The resulting VM has a graphical
desktop with QEMU guest agent and SPICE agent, suitable for testing
kerbside's SPICE console proxy.

When --host-address and --storage-path are provided, the script creates a
local-storage datacenter and cluster, registers the host as a hypervisor
(which triggers VDSM installation), and creates a local storage domain.
Without those flags, it assumes infrastructure already exists and just
creates the template and VM.
"""

import argparse
import logging
import random
import ssl
import sys
import time

import ovirtsdk4 as sdk
import ovirtsdk4.types as types


DEFAULT_WAIT_MINS = 30
DEFAULT_DISK_IMAGE = '/srv/ci/cached/debian-12-gnome-agents'
DEFAULT_TEMPLATE_NAME = 'desktop-spice'
DEFAULT_VM_MEMORY_MB = 2048
DEFAULT_HOST_NAME = 'local-host'


def parse_args():
    parser = argparse.ArgumentParser(
        description='Create an oVirt VM as a SPICE test target for kerbside.'
    )

    conn = parser.add_argument_group('connection')
    conn.add_argument(
        '--url', required=True,
        help='oVirt Engine API URL (e.g. https://ovirt.local/ovirt-engine/api)'
    )
    conn.add_argument('--username', default='admin@internal', help='oVirt username')
    conn.add_argument('--password', required=True, help='oVirt password')
    conn.add_argument('--ca-file', required=True, help='Path to CA certificate PEM file')

    infra = parser.add_argument_group('infrastructure')
    infra.add_argument('--datacenter', required=True, help='oVirt datacenter name')
    infra.add_argument('--cluster', required=True, help='oVirt cluster name')
    infra.add_argument('--storage-domain', required=True, help='Storage domain name')

    host = parser.add_argument_group('host setup (optional, creates infrastructure)')
    host.add_argument(
        '--host-address',
        help='FQDN or IP of the host to register as a hypervisor'
    )
    host.add_argument(
        '--host-password',
        help='Root password of the host (for oVirt to install VDSM via SSH)'
    )
    host.add_argument(
        '--host-name', default=DEFAULT_HOST_NAME,
        help='Name to assign the host in oVirt'
    )
    host.add_argument(
        '--storage-path',
        help='Local filesystem path for storage domain (e.g. /srv/ovirt-storage)'
    )

    vm = parser.add_argument_group('VM options')
    vm.add_argument(
        '--disk-image', default=DEFAULT_DISK_IMAGE,
        help='Path to QCOW2 disk image to upload'
    )
    vm.add_argument('--template-name', default=DEFAULT_TEMPLATE_NAME, help='Name for the created template')
    vm.add_argument('--vm-name', default=None, help='VM name (random if not specified)')
    vm.add_argument('--vm-memory-mb', type=int, default=DEFAULT_VM_MEMORY_MB, help='VM memory in MB')

    parser.add_argument(
        '--timeout-mins', type=int, default=DEFAULT_WAIT_MINS,
        help='Maximum minutes to wait for operations'
    )
    parser.add_argument('--debug', action='store_true', help='Enable oVirt SDK debug logging')

    args = parser.parse_args()

    if args.host_address and not args.host_password:
        parser.error('--host-password is required when --host-address is provided')
    if args.storage_path and not args.host_address:
        parser.error('--host-address is required when --storage-path is provided')

    return args


def _wait_for(description, check_fn, timeout_secs, poll_interval=5):
    """Poll check_fn until it returns a truthy value or timeout is reached."""
    start = time.time()
    while True:
        result = check_fn()
        if result:
            return result
        if time.time() - start > timeout_secs:
            print(f'ERROR: Timeout waiting for {description}')
            sys.exit(1)
        time.sleep(poll_interval)


def create_datacenter(system_service, datacenter_name):
    """Create a local-storage datacenter if it doesn't exist.

    Note: a local-storage datacenter stays in UNINITIALIZED state until a
    host with local storage is added. Do not wait for UP here.
    """
    dcs_service = system_service.data_centers_service()

    for dc in dcs_service.list():
        if dc.name == datacenter_name:
            print(f'Datacenter {datacenter_name!r} already exists (status: {dc.status})')
            return

    print(f'Creating local-storage datacenter {datacenter_name!r}...')
    dcs_service.add(
        types.DataCenter(
            name=datacenter_name,
            local=True,
        )
    )


def create_cluster(system_service, cluster_name, datacenter_name):
    """Create a cluster in the datacenter if it doesn't exist."""
    clusters_service = system_service.clusters_service()

    for c in clusters_service.list():
        if c.name == cluster_name:
            print(f'Cluster {cluster_name!r} already exists')
            return

    print(f'Creating cluster {cluster_name!r} in datacenter {datacenter_name!r}...')
    clusters_service.add(
        types.Cluster(
            name=cluster_name,
            data_center=types.DataCenter(name=datacenter_name),
            cpu=types.Cpu(
                architecture=types.Architecture.X86_64,
            ),
            # Use legacy Linux bridge networking (not OVS) so the
            # host-deploy Ansible role does not attempt OVN configuration.
            switch_type=types.SwitchType.LEGACY,
        )
    )
    print(f'  Cluster {cluster_name!r} created')


def _dump_events(system_service, search_query, label, max_events=20):
    """Print recent oVirt events matching a search query."""
    try:
        events_service = system_service.events_service()
        events = events_service.list(search=search_query, max=max_events)
        if events:
            print(f'\n--- Recent events for {label} ---')
            for event in sorted(events, key=lambda e: e.id):
                print(f'  [{event.severity}] {event.description}')
            print('--- End of events ---\n')
        else:
            print(f'  No events found for {label}')
    except Exception as e:
        print(f'  (Could not fetch events for {label}: {e})')


def _fix_management_network(system_service, host_service, host, datacenter_name):
    """Attach the ovirtmgmt management network to the host's NIC.

    When oVirt's automatic setupNetworks fails during host addition (common
    in CI / single-node setups), the host goes non_operational with
    "missing on host: 'ovirtmgmt'". We fix this by finding the host's
    primary NIC, attaching ovirtmgmt to it via the SDK, then activating
    the host.
    """
    # Find the ovirtmgmt network in our specific datacenter.
    # Each datacenter has its own ovirtmgmt with a unique ID; using the
    # wrong one (e.g. from the Default datacenter) causes a 400 error.
    dcs_service = system_service.data_centers_service()
    dc = None
    for d in dcs_service.list():
        if d.name == datacenter_name:
            dc = d
            break

    if not dc:
        print(f'ERROR: Could not find datacenter {datacenter_name!r}')
        sys.exit(1)

    dc_service = dcs_service.data_center_service(dc.id)
    dc_networks = dc_service.networks_service()
    ovirtmgmt = None
    for net in dc_networks.list():
        if net.name == 'ovirtmgmt':
            ovirtmgmt = net
            print(f'  Found ovirtmgmt network (id={ovirtmgmt.id}) in datacenter {datacenter_name!r}')
            break

    if not ovirtmgmt:
        print('ERROR: Could not find ovirtmgmt network in datacenter')
        sys.exit(1)

    # Find the host's primary NIC (the one with a default route / IP)
    nics_service = host_service.nics_service()
    target_nic = None
    for nic in nics_service.list():
        # Skip bridges, bonds, and loopback
        if nic.bridged or not nic.ip or nic.name == 'lo':
            continue
        if nic.ip.address and not nic.ip.address.startswith('127.'):
            target_nic = nic
            print(f'  Found NIC {nic.name!r} with IP {nic.ip.address}')
            break

    if not target_nic:
        # Fall back to first non-loopback NIC
        for nic in nics_service.list():
            if nic.name != 'lo' and not nic.bridged:
                target_nic = nic
                print(f'  Using fallback NIC {nic.name!r}')
                break

    if not target_nic:
        print('ERROR: Could not find a suitable NIC on the host')
        sys.exit(1)

    print(f'Attaching ovirtmgmt to NIC {target_nic.name!r}...')
    host_service.setup_networks(
        modified_network_attachments=[
            types.NetworkAttachment(
                network=types.Network(id=ovirtmgmt.id),
                host_nic=types.HostNic(name=target_nic.name),
                ip_address_assignments=[
                    types.IpAddressAssignment(
                        assignment_method=types.BootProtocol.DHCP,
                    ),
                ],
            ),
        ],
        check_connectivity=False,
        commit_on_success=True,
    )
    print('  Network configured, persisting...')
    host_service.commit_net_config()


def add_host(system_service, host_name, host_address, host_password, cluster_name, datacenter_name, timeout_secs):
    """Register a host as a hypervisor and wait for it to become active."""
    hosts_service = system_service.hosts_service()

    # Check if already registered
    for h in hosts_service.list():
        if h.address == host_address or h.name == host_name:
            print(f'Host {host_name!r} ({host_address}) already registered')
            host_name = h.name
            break
    else:
        print(f'Adding host {host_name!r} ({host_address}) to cluster {cluster_name!r}...')
        print('  This triggers VDSM installation and may take several minutes.')
        hosts_service.add(
            types.Host(
                name=host_name,
                address=host_address,
                root_password=host_password,
                cluster=types.Cluster(name=cluster_name),
            )
        )

    def check():
        for h in hosts_service.list():
            if h.name == host_name:
                print(f'  Host status: {h.status}')
                if h.status == types.HostStatus.UP:
                    return h
                if h.status == types.HostStatus.NON_OPERATIONAL:
                    return ('non_operational', h)
                if h.status in (
                    types.HostStatus.INSTALL_FAILED,
                    types.HostStatus.ERROR,
                ):
                    print(f'ERROR: Host entered {h.status} state')
                    _dump_events(system_service, f'host.name={h.name}', f'host {h.name!r}')
                    sys.exit(1)
        return None

    result = _wait_for(
        f'host {host_name!r} to be UP or non_operational',
        check, timeout_secs, poll_interval=15,
    )

    # If the host went non_operational, try to fix the management network
    if isinstance(result, tuple) and result[0] == 'non_operational':
        host = result[1]
        _dump_events(system_service, f'host.name={host.name}', f'host {host.name!r}')
        print('Attempting to fix management network configuration...')

        host_service = hosts_service.host_service(host.id)
        _fix_management_network(system_service, host_service, host, datacenter_name)

        # Activate the host, retrying if a prior operation is still
        # in progress (the setup_networks call may not have fully
        # completed on the engine side).
        print('Activating host...')
        activate_start = time.time()
        while True:
            try:
                host_service.activate()
                break
            except sdk.Error as e:
                if 'in progress' in str(e) and time.time() - activate_start < 120:
                    print('  Activate busy, retrying in 10s...')
                    time.sleep(10)
                else:
                    raise

        # Now wait for the host to come UP
        def check_up():
            h = host_service.get()
            print(f'  Host status: {h.status}')
            if h.status == types.HostStatus.UP:
                return h
            if h.status in (
                types.HostStatus.INSTALL_FAILED,
                types.HostStatus.ERROR,
                types.HostStatus.NON_OPERATIONAL,
            ):
                print(f'ERROR: Host still in {h.status} after network fix')
                _dump_events(system_service, f'host.name={h.name}', f'host {h.name!r}')
                sys.exit(1)
            return None

        result = _wait_for(
            f'host {host_name!r} to be UP after network fix',
            check_up, timeout_secs, poll_interval=10,
        )

    return result


def create_local_storage(
    system_service, storage_domain_name, host_name, storage_path,
    datacenter_name, timeout_secs,
):
    """Create a local storage domain if it doesn't exist."""
    sds_service = system_service.storage_domains_service()

    for sd in sds_service.list():
        if sd.name == storage_domain_name:
            print(f'Storage domain {storage_domain_name!r} already exists')
            return

    print(f'Creating local storage domain {storage_domain_name!r} at {storage_path}...')
    sds_service.add(
        types.StorageDomain(
            name=storage_domain_name,
            type=types.StorageDomainType.DATA,
            storage=types.HostStorage(
                type=types.StorageType.LOCALFS,
                path=storage_path,
            ),
            host=types.Host(name=host_name),
        )
    )

    # Wait for storage domain to become active. For local storage
    # domains, the top-level status is always None — we must check
    # via the datacenter's attached storage domains instead.
    dcs_service = system_service.data_centers_service()
    dc = None
    for d in dcs_service.list():
        if d.name == datacenter_name:
            dc = d
            break

    dc_sds_service = dcs_service.data_center_service(dc.id).storage_domains_service()

    def check():
        for sd in dc_sds_service.list():
            if sd.name == storage_domain_name:
                print(f'  Storage domain status: {sd.status}')
                if sd.status == types.StorageDomainStatus.ACTIVE:
                    return sd
                return None
        # Not yet attached to datacenter
        print('  Storage domain not yet attached to datacenter')
        return None

    _wait_for(
        f'storage domain {storage_domain_name!r} to be active',
        check, timeout_secs,
    )
    print(f'  Storage domain {storage_domain_name!r} is active')


def wait_for_datacenter(system_service, datacenter_name, timeout_secs):
    """Wait for an existing datacenter to reach UP status."""
    print(f'Waiting for datacenter {datacenter_name!r} to be ready...')
    dcs_service = system_service.data_centers_service()

    def check():
        for dc in dcs_service.list():
            if dc.name == datacenter_name and dc.status == types.DataCenterStatus.UP:
                print(f'  Datacenter {datacenter_name!r} is UP')
                return dc
        return None

    return _wait_for(f'datacenter {datacenter_name!r}', check, timeout_secs)


def upload_disk_image(connection, system_service, disk_image_path, storage_domain_name, timeout_secs):
    """Upload a QCOW2 disk image to oVirt and return the disk object.

    Uses the oVirt ImageIO transfer API to upload a local QCOW2 file as a
    new disk in the specified storage domain.
    """
    import json
    import os
    import http.client
    import subprocess
    from urllib.parse import urlparse

    image_size = os.path.getsize(disk_image_path)

    # Get the virtual size from the QCOW2 header so we can set
    # provisioned_size correctly. oVirt requires this to match the
    # image's virtual size; an arbitrary value causes 'illegal' disks.
    try:
        qemu_info = subprocess.check_output(
            ['qemu-img', 'info', '--output=json', disk_image_path],
            stderr=subprocess.STDOUT,
        )
        virtual_size = json.loads(qemu_info)['virtual-size']
    except (subprocess.CalledProcessError, FileNotFoundError, KeyError) as e:
        print(f'  Warning: could not determine virtual size ({e}), '
              f'falling back to 2x file size')
        virtual_size = image_size * 2

    print(f'Uploading disk image {disk_image_path} '
          f'({image_size} bytes, virtual {virtual_size} bytes)...')

    # Create the disk that will receive the upload
    disks_service = system_service.disks_service()
    disk = disks_service.add(
        types.Disk(
            name='desktop-spice-disk',
            content_type=types.DiskContentType.DATA,
            format=types.DiskFormat.COW,
            initial_size=image_size,
            provisioned_size=virtual_size,
            storage_domains=[
                types.StorageDomain(name=storage_domain_name),
            ],
        )
    )
    print(f'  Created disk {disk.id}')

    # Wait for the disk to be ready
    disk_service = disks_service.disk_service(disk.id)

    def check_disk():
        try:
            d = disk_service.get()
        except sdk.NotFoundError:
            print('  Disk was removed by oVirt (404)')
            _dump_events(
                system_service, f'disk.id={disk.id}',
                f'disk {disk.id}',
            )
            print('ERROR: Disk disappeared after upload — oVirt '
                  'likely rejected the image data')
            sys.exit(1)

        print(f'  Disk status: {d.status}')
        if d.status == types.DiskStatus.ILLEGAL:
            _dump_events(
                system_service, f'disk.id={disk.id}',
                f'disk {disk.id}',
            )
            print('ERROR: Disk entered illegal state — the '
                  'uploaded image was rejected by oVirt')
            sys.exit(1)
        return d if d.status == types.DiskStatus.OK else None

    _wait_for('disk to be ready', check_disk, timeout_secs)

    # Start an upload transfer
    transfers_service = system_service.image_transfers_service()
    transfer = transfers_service.add(
        types.ImageTransfer(
            disk=types.Disk(id=disk.id),
            direction=types.ImageTransferDirection.UPLOAD,
            format=types.DiskFormat.COW,
        )
    )
    print(f'  Transfer started (id={transfer.id})')

    # Wait for the transfer to be ready
    transfer_service = transfers_service.image_transfer_service(transfer.id)

    def check_transfer():
        t = transfer_service.get()
        return t if t.phase == types.ImageTransferPhase.TRANSFERRING else None

    transfer = _wait_for('image transfer to be ready', check_transfer, timeout_secs)

    # Upload the image data via HTTPS to the transfer URL.
    # Prefer transfer_url (direct to imageio daemon) but fall back
    # to proxy_url (through the engine) if it is not set.
    upload_url = transfer.transfer_url or transfer.proxy_url
    print(f'  Uploading to {upload_url}...')

    parsed = urlparse(upload_url)
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    conn = http.client.HTTPSConnection(parsed.hostname, parsed.port, context=context)
    with open(disk_image_path, 'rb') as f:
        conn.putrequest('PUT', parsed.path)
        conn.putheader('Content-Length', str(image_size))
        conn.putheader('Content-Type', 'application/octet-stream')
        conn.endheaders()

        chunk_size = 64 * 1024
        sent = 0
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            conn.send(chunk)
            sent += len(chunk)
            if sent % (10 * 1024 * 1024) < chunk_size:
                print(f'  Uploaded {sent // (1024 * 1024)} MB / '
                      f'{image_size // (1024 * 1024)} MB')

    response = conn.getresponse()
    print(f'  Upload response: {response.status} {response.reason}')
    if response.status >= 400:
        body = response.read().decode('utf-8', errors='replace')
        conn.close()
        print(f'  Upload error body: {body[:500]}')
        print('ERROR: Image upload failed')
        sys.exit(1)
    conn.close()

    # Finalize the transfer
    transfer_service.finalize()
    print('  Transfer finalized')

    # Wait for the disk to become OK again
    _wait_for('disk to be ready after upload', check_disk, timeout_secs)
    print(f'  Disk {disk.id} uploaded successfully')

    return disk


def create_template_from_disk(system_service, disk, template_name, cluster_name, timeout_secs):
    """Create a VM template from an uploaded disk."""
    templates_service = system_service.templates_service()

    for t in templates_service.list():
        if t.name == template_name:
            print(f'Template {template_name!r} already exists, skipping')
            return

    # Create a temporary VM with the disk attached, then make a template
    vms_service = system_service.vms_service()
    temp_vm_name = f'template-builder-{random.randint(0, 9999):04d}'

    print(f'Creating temporary VM {temp_vm_name!r} for template...')
    vm = vms_service.add(
        types.Vm(
            name=temp_vm_name,
            cluster=types.Cluster(name=cluster_name),
            template=types.Template(name='Blank'),
            os=types.OperatingSystem(
                boot=types.Boot(devices=[types.BootDevice.HD]),
            ),
            memory=2048 * 1024 * 1024,
            display=types.Display(type=types.DisplayType.SPICE),
        )
    )
    vm_service = vms_service.vm_service(vm.id)

    # Wait for temp VM to be down (ready)
    def check_vm_down():
        v = vm_service.get()
        return v if v.status == types.VmStatus.DOWN else None

    _wait_for('temp VM to be ready', check_vm_down, timeout_secs)

    # Attach the uploaded disk to the VM
    disk_attachments_service = vm_service.disk_attachments_service()
    disk_attachments_service.add(
        types.DiskAttachment(
            disk=types.Disk(id=disk.id),
            interface=types.DiskInterface.VIRTIO,
            bootable=True,
            active=True,
        )
    )
    print('  Disk attached to temp VM')

    # Create template from the VM
    print(f'Creating template {template_name!r}...')
    templates_service.add(
        types.Template(
            name=template_name,
            vm=types.Vm(id=vm.id),
        )
    )

    # Wait for template to be available
    def check_template():
        for t in templates_service.list():
            if t.name == template_name and t.status == types.TemplateStatus.OK:
                return t
        return None

    _wait_for(f'template {template_name!r} to be ready', check_template, timeout_secs)
    print(f'  Template {template_name!r} is available')

    # Delete the temporary VM (the template has its own copy of the disk)
    print(f'  Removing temporary VM {temp_vm_name!r}...')
    vm_service.remove()

    return template_name


def create_and_start_vm(system_service, vm_name, template_name, cluster_name, memory_mb, timeout_secs):
    """Create a VM from the template and start it."""
    vms_service = system_service.vms_service()
    memory_bytes = memory_mb * 1024 * 1024

    start = time.time()
    while True:
        print(f'Creating VM {vm_name!r}...')
        try:
            vms_service.add(
                types.Vm(
                    name=vm_name,
                    memory=memory_bytes,
                    cluster=types.Cluster(name=cluster_name),
                    template=types.Template(name=template_name),
                    display=types.Display(type=types.DisplayType.SPICE),
                    os=types.OperatingSystem(
                        boot=types.Boot(devices=[types.BootDevice.HD])
                    ),
                ),
            )
            break
        except Exception as e:
            print(f'  Create failed ({e}), retrying...')
            time.sleep(5)

        if time.time() - start > timeout_secs:
            print(f'ERROR: Timeout trying to create VM {vm_name!r}')
            sys.exit(1)

    vm = vms_service.list(search=f'name={vm_name}')[0]
    vm_service = vms_service.vm_service(vm.id)

    # Wait for VM to be ready to start
    def check_down():
        v = vm_service.get()
        print(f'  VM status: {v.status}')
        return v if v.status == types.VmStatus.DOWN else None

    _wait_for(f'VM {vm_name!r} to be ready', check_down, timeout_secs)

    # Start the VM, retrying if it falls back to DOWN
    max_start_attempts = 3
    for attempt in range(1, max_start_attempts + 1):
        print(f'Starting VM {vm_name!r} (attempt {attempt}/{max_start_attempts})...')
        try:
            vm_service.start()
        except Exception as e:
            if 'Up status' in str(e):
                print(f'VM {vm_name!r} is already running')
                return vm_name
            raise

        start_time = time.time()
        while time.time() - start_time < 120:
            v = vm_service.get()
            print(f'  VM status: {v.status}')
            if v.status == types.VmStatus.UP:
                print(f'VM {vm_name!r} is running')
                return vm_name
            if v.status == types.VmStatus.POWERING_UP:
                # VM is booting, guest agent may not have responded yet.
                # Keep waiting — oVirt will transition to UP once the
                # guest agent connects.
                pass
            elif v.status == types.VmStatus.DOWN:
                # VM fell back to down after start attempt
                break
            time.sleep(5)

        # Check if VM ended up running while we were logging
        v = vm_service.get()
        if v.status in (types.VmStatus.UP, types.VmStatus.POWERING_UP):
            print(f'VM {vm_name!r} is running (status: {v.status})')
            return vm_name

        # Dump events to understand why the VM didn't start
        print('  VM went back to DOWN, checking events...')
        _dump_events(
            system_service, f'vm.name={vm_name}',
            f'VM {vm_name!r}', max_events=5,
        )

        if attempt < max_start_attempts:
            print('  Retrying in 15s...')
            time.sleep(15)

    print(f'ERROR: VM {vm_name!r} failed to start after {max_start_attempts} attempts')
    _dump_events(
        system_service, f'vm.name={vm_name}',
        f'VM {vm_name!r}', max_events=10,
    )
    sys.exit(1)


def main():
    args = parse_args()
    vm_name = args.vm_name or f'kerbside-test-{random.randint(0, 9999):04d}'
    timeout_secs = args.timeout_mins * 60

    log_kwargs = {}
    if args.debug:
        log_kwargs['debug'] = True
        log_kwargs['log'] = logging.getLogger()

    # The oVirt engine may not be fully ready to accept API connections
    # immediately after engine-setup completes (SSO service returns HTML
    # instead of JSON). Retry the connection until it succeeds.
    connection = None
    print('Connecting to oVirt engine...')
    start = time.time()
    while True:
        try:
            connection = sdk.Connection(
                url=args.url,
                username=args.username,
                password=args.password,
                ca_file=args.ca_file,
                **log_kwargs,
            )
            # Force authentication by making an API call
            connection.system_service().data_centers_service().list()
            break
        except sdk.Error as e:
            if connection:
                try:
                    connection.close()
                except Exception:
                    pass
                connection = None
            if time.time() - start > timeout_secs:
                print(f'ERROR: Timeout waiting for oVirt engine to be ready: {e}')
                sys.exit(1)
            print(f'  Engine not ready ({e}), retrying in 10s...')
            time.sleep(10)

    print('  Connected to oVirt engine')

    try:
        system_service = connection.system_service()

        if args.host_address:
            # Full infrastructure setup: datacenter, cluster, host, storage.
            # A local-storage datacenter won't reach UP until a host with
            # storage is added, so create it without waiting, then add the
            # host and storage, then wait for the datacenter to come UP.
            create_datacenter(system_service, args.datacenter)
            create_cluster(system_service, args.cluster, args.datacenter)
            add_host(
                system_service, args.host_name, args.host_address,
                args.host_password, args.cluster, args.datacenter,
                timeout_secs,
            )
            if args.storage_path:
                create_local_storage(
                    system_service, args.storage_domain, args.host_name,
                    args.storage_path, args.datacenter, timeout_secs,
                )
            wait_for_datacenter(system_service, args.datacenter, timeout_secs)
        else:
            # Assume infrastructure exists, just wait for datacenter
            wait_for_datacenter(system_service, args.datacenter, timeout_secs)

        disk = upload_disk_image(
            connection, system_service, args.disk_image,
            args.storage_domain, timeout_secs,
        )
        create_template_from_disk(
            system_service, disk, args.template_name,
            args.cluster, timeout_secs,
        )
        create_and_start_vm(
            system_service, vm_name, args.template_name,
            args.cluster, args.vm_memory_mb, timeout_secs,
        )

        print(f'\nDone. VM {vm_name!r} is ready as a SPICE test target.')
    finally:
        connection.close()


if __name__ == '__main__':
    main()
