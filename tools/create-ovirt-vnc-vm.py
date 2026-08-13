#!/usr/bin/python3

"""Create a running oVirt VM that has no SPICE console.

Kerbside's oVirt source driver walks every VM the engine reports and
brokers the ones that are up and offer a SPICE graphics console. A VM
that is up but offers only VNC is the interesting case: the driver has
to skip it and carry on. It used to dereference the missing console
instead, which errored the whole source, dropped every VM discovered
after it, and reaped their consoles from the database as "no longer
available" -- once a minute, forever.

Nothing in the lane exercised that path, because every VM
shakenfist/actions' start-test-target.py creates has a SPICE display.
This script adds the missing shape: a diskless, network-boot VM with a
VNC display, started and waited for until the engine reports it up.

It is deliberately cheap. The VM has no disk (nothing needs to boot --
the engine reporting it as up is the entire point), 512MB of memory,
and a NIC on ovirtmgmt so network boot is a legitimate boot sequence
rather than a VM the engine may refuse to run.

The name must not collide with the SPICE VM's `smoke-test-` prefix:
tools/test-ovirt-console.py and tools/ovirt-e2e/drive-console.py both
select the VM under test by that prefix, and drive-console.py asserts
this VM is absent from kerbside's console list.

Runs on the oVirt target, alongside test-ovirt-console.py, so it can
use the engine's own CA at /etc/pki/ovirt-engine/ca.pem.
"""

import argparse
import sys
import time

import ovirtsdk4 as sdk
import ovirtsdk4.types as types


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', required=True, help='oVirt Engine API URL')
    parser.add_argument('--username', default='admin@internal')
    parser.add_argument('--password', required=True)
    parser.add_argument('--ca-file', required=True)
    parser.add_argument(
        '--name', default='no-spice-test',
        help='VM name; must not start with smoke-test- (default: '
             '%(default)s)')
    parser.add_argument('--cluster', default='test')
    parser.add_argument(
        '--network', default='ovirtmgmt',
        help='Network to attach the NIC to (default: %(default)s)')
    parser.add_argument(
        '--memory-mb', type=int, default=512,
        help='VM memory in MB (default: %(default)s)')
    parser.add_argument(
        '--timeout-mins', type=int, default=5,
        help='How long to wait for each state change (default: %(default)s)')
    return parser.parse_args()


def _log(msg):
    print('[create-vnc-vm] %s' % msg)
    sys.stdout.flush()


def _resolve_vnic_profile(system_service, cluster_name, network_name):
    """Find the vNIC profile for `network_name` as `cluster_name` sees it.

    Every datacenter gets its own network named ovirtmgmt, each with a
    distinct id and its own vNIC profile. This lane has two of them: the
    `Default` datacenter engine-setup creates, and the `test` datacenter
    start-test-target.py creates. Picking a profile by name alone takes
    whichever the engine happens to list first, and attaching the wrong
    datacenter's profile fails with HTTP 409 "The specified Logical
    Network doesn't exist in the current Cluster" -- intermittently,
    because the listing order is not guaranteed.

    So resolve the network through the cluster that will host the VM,
    which is the same constraint the engine enforces, and take the
    profile from that network. shakenfist/actions' start-test-target.py
    guards the same hazard in _fix_management_network().
    """
    clusters = system_service.clusters_service().list()
    cluster = None
    for c in clusters:
        if c.name == cluster_name:
            cluster = c
            break
    if cluster is None:
        raise SystemExit(
            'ERROR: no cluster named %s; available: %s'
            % (cluster_name,
               ', '.join(sorted(c.name for c in clusters)) or '(none)'))

    cluster_service = system_service.clusters_service().cluster_service(
        cluster.id)
    networks = cluster_service.networks_service().list()
    network = None
    for n in networks:
        if n.name == network_name:
            network = n
            break
    if network is None:
        raise SystemExit(
            'ERROR: cluster %s has no network named %s; it has: %s'
            % (cluster_name, network_name,
               ', '.join(sorted(n.name for n in networks)) or '(none)'))

    network_service = system_service.networks_service().network_service(
        network.id)
    profiles = network_service.vnic_profiles_service().list()
    if not profiles:
        raise SystemExit(
            'ERROR: network %s (id %s) on cluster %s has no vNIC profiles'
            % (network_name, network.id, cluster_name))

    # A network normally has exactly one profile, sharing its name.
    # Prefer that one, but any profile on this network is attachable to
    # a VM in this cluster, which is the property that matters.
    for p in profiles:
        if p.name == network_name:
            return p
    return profiles[0]


def _wait_for_status(vm_service, wanted, timeout_secs):
    """Poll a VM until it reports one of `wanted`, or give up loudly."""
    deadline = time.time() + timeout_secs
    seen = None
    while time.time() < deadline:
        seen = vm_service.get().status
        if seen in wanted:
            return seen
        time.sleep(5)
    raise SystemExit(
        'ERROR: VM did not reach %s within %ds (last status %s)'
        % ('/'.join(str(w) for w in wanted), timeout_secs, seen))


def main():
    args = parse_args()
    timeout_secs = args.timeout_mins * 60

    if args.name.startswith('smoke-test-'):
        raise SystemExit(
            'ERROR: --name must not start with smoke-test-; that prefix '
            'selects the SPICE VM under test and this VM would be '
            'mistaken for it')

    connection = sdk.Connection(
        url=args.url, username=args.username, password=args.password,
        ca_file=args.ca_file)
    try:
        system_service = connection.system_service()
        vms_service = system_service.vms_service()

        existing = vms_service.list(search='name=%s' % args.name)
        if existing:
            _log('VM %s already exists, reusing it' % args.name)
            vm = existing[0]
        else:
            _log('creating diskless VNC VM %s on cluster %s'
                 % (args.name, args.cluster))
            vm = vms_service.add(
                types.Vm(
                    name=args.name,
                    description='No SPICE console; kerbside must skip it',
                    cluster=types.Cluster(name=args.cluster),
                    template=types.Template(name='Blank'),
                    memory=args.memory_mb * 1024 * 1024,
                    display=types.Display(type=types.DisplayType.VNC),
                    os=types.OperatingSystem(
                        boot=types.Boot(
                            devices=[types.BootDevice.NETWORK])),
                )
            )

        vm_service = vms_service.vm_service(vm.id)
        _log('waiting for %s to settle before starting it' % args.name)
        _wait_for_status(
            vm_service, (types.VmStatus.DOWN, types.VmStatus.UP),
            timeout_secs)

        if not vm_service.nics_service().list():
            profile = _resolve_vnic_profile(
                system_service, args.cluster, args.network)
            _log('attaching a NIC on %s (vNIC profile %s, id %s)'
                 % (args.network, profile.name, profile.id))
            vm_service.nics_service().add(
                types.Nic(name='nic1',
                          vnic_profile=types.VnicProfile(id=profile.id)))

        if vm_service.get().status != types.VmStatus.UP:
            _log('starting %s' % args.name)
            vm_service.start()

        _wait_for_status(vm_service, (types.VmStatus.UP,), timeout_secs)

        # Confirm the shape this VM exists to provide. A VM the engine
        # hands a SPICE console to would not exercise the skip path, and
        # would silently turn this guard into a no-op.
        consoles = vm_service.graphics_consoles_service().list(current=True)
        protocols = [str(c.protocol) for c in consoles]
        _log('%s is up with graphics consoles: %s'
             % (args.name, ', '.join(protocols) or '(none)'))
        if str(types.GraphicsType.SPICE) in protocols:
            raise SystemExit(
                'ERROR: %s was given a SPICE console (%s), so it does not '
                'test the no-SPICE path it exists for'
                % (args.name, ', '.join(protocols)))

        return 0

    finally:
        connection.close()


if __name__ == '__main__':
    sys.exit(main())
