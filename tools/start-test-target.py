#!/usr/bin/python3

"""Create an oVirt VM suitable as a SPICE test target for kerbside.

This script imports a CirrOS image from oVirt's built-in Glance image
repository, creates a template from it, then creates and starts a VM
from that template. The resulting VM can be used as a SPICE console
target for kerbside functional tests.
"""

import argparse
import logging
import random
import sys
import time

import ovirtsdk4 as sdk
import ovirtsdk4.types as types


DEFAULT_WAIT_MINS = 15
DEFAULT_IMAGE_NAME = 'CirrOS 0.5'
DEFAULT_TEMPLATE_NAME = 'cirros'
DEFAULT_VM_MEMORY_MB = 2048


def parse_args():
    parser = argparse.ArgumentParser(
        description='Create an oVirt VM as a SPICE test target for kerbside.'
    )
    parser.add_argument(
        '--url', required=True,
        help='oVirt Engine API URL (e.g. https://ovirt-engine.example/ovirt-engine/api)'
    )
    parser.add_argument('--username', default='admin@internal', help='oVirt username')
    parser.add_argument('--password', required=True, help='oVirt password')
    parser.add_argument('--ca-file', required=True, help='Path to CA certificate PEM file')
    parser.add_argument('--datacenter', required=True, help='oVirt datacenter name')
    parser.add_argument('--cluster', required=True, help='oVirt cluster name')
    parser.add_argument('--storage-domain', required=True, help='Storage domain for the template disk')
    parser.add_argument('--image-name', default=DEFAULT_IMAGE_NAME, help='Glance image name prefix to import')
    parser.add_argument('--template-name', default=DEFAULT_TEMPLATE_NAME, help='Name for the created template')
    parser.add_argument('--vm-name', default=None, help='VM name (random if not specified)')
    parser.add_argument('--vm-memory-mb', type=int, default=DEFAULT_VM_MEMORY_MB, help='VM memory in MB')
    parser.add_argument(
        '--timeout-mins', type=int, default=DEFAULT_WAIT_MINS,
        help='Maximum minutes to wait for operations'
    )
    parser.add_argument('--debug', action='store_true', help='Enable oVirt SDK debug logging')
    return parser.parse_args()


def wait_for_datacenter(system_service, datacenter_name, timeout_secs):
    """Wait for the named datacenter to reach UP status."""
    print(f'Waiting for datacenter {datacenter_name!r} to be ready...')
    datacenters_service = system_service.data_centers_service()

    start = time.time()
    while True:
        for dc in datacenters_service.list():
            if dc.name == datacenter_name and dc.status == types.DataCenterStatus.UP:
                print(f'  Datacenter {datacenter_name!r} is UP')
                return dc

        if time.time() - start > timeout_secs:
            print(f'ERROR: Timeout waiting for datacenter {datacenter_name!r}')
            sys.exit(1)
        time.sleep(5)


def import_template(system_service, image_name, template_name, cluster_name, storage_domain_name):
    """Import a Glance image as a template if it doesn't already exist."""
    # Check if template already exists
    templates_service = system_service.templates_service()
    for t in templates_service.list():
        if t.name == template_name:
            print(f'Template {template_name!r} already exists, skipping import')
            return

    # Find the image in the built-in Glance repository
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

    # Import the image as a template
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

    start = time.time()
    while True:
        for t in templates_service.list():
            if t.name == template_name:
                print(f'  Template {template_name!r} is available')
                time.sleep(5)  # Allow oVirt to finish making it available
                return

        if time.time() - start > timeout_secs:
            print(f'ERROR: Timeout waiting for template {template_name!r}')
            sys.exit(1)
        time.sleep(5)


def create_and_start_vm(system_service, vm_name, template_name, cluster_name, memory_mb, timeout_secs):
    """Create a VM from the template and start it."""
    vms_service = system_service.vms_service()
    memory_bytes = memory_mb * 1024 * 1024

    # Create the VM
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
    for _ in range(36):
        time.sleep(5)
        vm = vm_service.get()
        print(f'  VM status: {vm.status}')
        if vm.status == types.VmStatus.DOWN:
            break

    # Start the VM
    print(f'Starting VM {vm_name!r}...')
    vm_service.start()

    for _ in range(36):
        time.sleep(5)
        vm = vm_service.get()
        print(f'  VM status: {vm.status}')
        if vm.status == types.VmStatus.UP:
            print(f'VM {vm_name!r} is running')
            return vm_name

    print(f'WARNING: VM {vm_name!r} did not reach UP status')
    return vm_name


def main():
    args = parse_args()
    vm_name = args.vm_name or f'kerbside-test-{random.randint(0, 9999):04d}'
    timeout_secs = args.timeout_mins * 60

    log_kwargs = {}
    if args.debug:
        log_kwargs['debug'] = True
        log_kwargs['log'] = logging.getLogger()

    connection = sdk.Connection(
        url=args.url,
        username=args.username,
        password=args.password,
        ca_file=args.ca_file,
        **log_kwargs,
    )

    try:
        system_service = connection.system_service()

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
