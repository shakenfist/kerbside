#!/usr/bin/python3

"""Create an oVirt VM suitable as a SPICE test target for kerbside.

This script can optionally set up the full oVirt infrastructure (datacenter,
cluster, hypervisor host, local storage domain) before importing a CirrOS
image from oVirt's built-in Glance image repository, creating a template,
and starting a VM. The resulting VM can be used as a SPICE console target
for kerbside functional tests.

When --host-address and --storage-path are provided, the script creates a
local-storage datacenter and cluster, registers the host as a hypervisor
(which triggers VDSM installation), and creates a local storage domain.
Without those flags, it assumes infrastructure already exists and just
creates the template and VM.
"""

import argparse
import logging
import random
import sys
import time

import ovirtsdk4 as sdk
import ovirtsdk4.types as types


DEFAULT_WAIT_MINS = 30
DEFAULT_IMAGE_NAME = 'CirrOS 0.5'
DEFAULT_TEMPLATE_NAME = 'cirros'
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
    vm.add_argument('--image-name', default=DEFAULT_IMAGE_NAME, help='Glance image name prefix to import')
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


def create_datacenter(system_service, datacenter_name, timeout_secs):
    """Create a local-storage datacenter if it doesn't exist, then wait for UP."""
    dcs_service = system_service.data_centers_service()

    # Check if it already exists
    for dc in dcs_service.list():
        if dc.name == datacenter_name:
            print(f'Datacenter {datacenter_name!r} already exists')
            break
    else:
        print(f'Creating local-storage datacenter {datacenter_name!r}...')
        dcs_service.add(
            types.DataCenter(
                name=datacenter_name,
                local=True,
            )
        )

    print(f'Waiting for datacenter {datacenter_name!r} to be ready...')

    def check():
        for dc in dcs_service.list():
            if dc.name == datacenter_name and dc.status == types.DataCenterStatus.UP:
                print(f'  Datacenter {datacenter_name!r} is UP')
                return dc
        return None

    return _wait_for(f'datacenter {datacenter_name!r}', check, timeout_secs)


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
        )
    )
    print(f'  Cluster {cluster_name!r} created')


def add_host(system_service, host_name, host_address, host_password, cluster_name, timeout_secs):
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
                if h.status in (
                    types.HostStatus.INSTALL_FAILED,
                    types.HostStatus.NON_OPERATIONAL,
                    types.HostStatus.ERROR,
                ):
                    print(f'ERROR: Host entered {h.status} state')
                    sys.exit(1)
        return None

    return _wait_for(
        f'host {host_name!r} to be UP', check, timeout_secs, poll_interval=15
    )


def create_local_storage(system_service, storage_domain_name, host_name, storage_path, timeout_secs):
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

    # Wait for storage domain to become active
    def check():
        for sd in sds_service.list():
            if sd.name == storage_domain_name:
                print(f'  Storage domain status: {sd.status}')
                if sd.status == types.StorageDomainStatus.ACTIVE:
                    return sd
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


def import_template(system_service, image_name, template_name, cluster_name, storage_domain_name):
    """Import a Glance image as a template if it doesn't already exist."""
    templates_service = system_service.templates_service()
    for t in templates_service.list():
        if t.name == template_name:
            print(f'Template {template_name!r} already exists, skipping import')
            return

    print('Finding ovirt-image-repository...')
    storage_domains_service = system_service.storage_domains_service()
    glance_domain = storage_domains_service.list(search='name=ovirt-image-repository')[0]
    glance_service = storage_domains_service.storage_domain_service(glance_domain.id)
    images_service = glance_service.images_service()

    image = None
    for img in images_service.list():
        if img.name.startswith(image_name):
            print(f'  Found image: {img.name}')
            image = img
            break

    if not image:
        print(f'ERROR: No image matching {image_name!r} found in Glance repository')
        sys.exit(1)

    done = False
    while not done:
        try:
            print(f'Importing image as template {template_name!r}...')
            target_image_service = images_service.image_service(image.id)
            target_image_service.import_(
                import_as_template=True,
                template=types.Template(name=template_name),
                cluster=types.Cluster(name=cluster_name),
                storage_domain=types.StorageDomain(name=storage_domain_name),
            )
            done = True
        except Exception as e:
            print(f'  Import failed ({e}), retrying...')
            time.sleep(5)

    print(f'  Template {template_name!r} import started')


def wait_for_template(system_service, template_name, timeout_secs):
    """Wait for the template to become available."""
    print(f'Waiting for template {template_name!r} to be available...')
    templates_service = system_service.templates_service()

    def check():
        for t in templates_service.list():
            if t.name == template_name:
                print(f'  Template {template_name!r} is available')
                return t
        return None

    _wait_for(f'template {template_name!r}', check, timeout_secs)
    time.sleep(5)  # Allow oVirt to finish making it available


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

    # Start the VM
    print(f'Starting VM {vm_name!r}...')
    vm_service.start()

    def check_up():
        v = vm_service.get()
        print(f'  VM status: {v.status}')
        return v if v.status == types.VmStatus.UP else None

    result = _wait_for(f'VM {vm_name!r} to be UP', check_up, timeout_secs)
    if result:
        print(f'VM {vm_name!r} is running')
    return vm_name


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
            # Full infrastructure setup: datacenter, cluster, host, storage
            create_datacenter(system_service, args.datacenter, timeout_secs)
            create_cluster(system_service, args.cluster, args.datacenter)
            add_host(
                system_service, args.host_name, args.host_address,
                args.host_password, args.cluster, timeout_secs,
            )
            if args.storage_path:
                create_local_storage(
                    system_service, args.storage_domain, args.host_name,
                    args.storage_path, timeout_secs,
                )
        else:
            # Assume infrastructure exists, just wait for datacenter
            wait_for_datacenter(system_service, args.datacenter, timeout_secs)

        import_template(
            system_service, args.image_name, args.template_name,
            args.cluster, args.storage_domain,
        )
        wait_for_template(system_service, args.template_name, timeout_secs)
        create_and_start_vm(
            system_service, vm_name, args.template_name,
            args.cluster, args.vm_memory_mb, timeout_secs,
        )

        print(f'\nDone. VM {vm_name!r} is ready as a SPICE test target.')
    finally:
        connection.close()


if __name__ == '__main__':
    main()
