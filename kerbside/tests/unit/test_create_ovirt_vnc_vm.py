import importlib.util
import sys
from pathlib import Path
from unittest import mock

import testtools


# create-ovirt-vnc-vm.py lives in tools/ (outside the importable package)
# and its filename contains a hyphen, so load it as a module by path.
#
# It imports ovirtsdk4 at module scope, which is deliberately not a test
# dependency: the script runs on the oVirt target against the engine's
# own system-wide SDK. Stub the import out. Nothing exercised here
# touches the SDK -- _resolve_vnic_profile only walks the services it is
# handed.
_CREATE_VNC_VM_PATH = (
    Path(__file__).resolve().parents[3] / 'tools' / 'create-ovirt-vnc-vm.py')


def _load_tool():
    spec = importlib.util.spec_from_file_location(
        'create_ovirt_vnc_vm', _CREATE_VNC_VM_PATH)
    module = importlib.util.module_from_spec(spec)
    sdk = mock.Mock()
    with mock.patch.dict(sys.modules,
                         {'ovirtsdk4': sdk, 'ovirtsdk4.types': sdk.types}):
        spec.loader.exec_module(module)
    return module


create_ovirt_vnc_vm = _load_tool()


class _Named(object):
    """Anything the SDK returns that we select by name."""

    def __init__(self, id, name):
        self.id = id
        self.name = name


class _FakeVnicProfilesService(object):
    def __init__(self, profiles):
        self._profiles = profiles

    def list(self):
        return self._profiles


class _FakeNetworkService(object):
    def __init__(self, profiles):
        self._profiles = profiles

    def vnic_profiles_service(self):
        return _FakeVnicProfilesService(self._profiles)


class _FakeNetworksService(object):
    """Serves both the cluster-scoped and system-wide network services."""

    def __init__(self, networks, profiles_by_network_id):
        self._networks = networks
        self._profiles_by_network_id = profiles_by_network_id

    def list(self):
        return self._networks

    def network_service(self, network_id):
        return _FakeNetworkService(
            self._profiles_by_network_id.get(network_id, []))


class _FakeClusterService(object):
    def __init__(self, networks, profiles_by_network_id):
        self._networks = networks
        self._profiles_by_network_id = profiles_by_network_id

    def networks_service(self):
        return _FakeNetworksService(
            self._networks, self._profiles_by_network_id)


class _FakeClustersService(object):
    def __init__(self, clusters, networks_by_cluster_id,
                 profiles_by_network_id):
        self._clusters = clusters
        self._networks_by_cluster_id = networks_by_cluster_id
        self._profiles_by_network_id = profiles_by_network_id

    def list(self):
        return self._clusters

    def cluster_service(self, cluster_id):
        return _FakeClusterService(
            self._networks_by_cluster_id.get(cluster_id, []),
            self._profiles_by_network_id)


class _FakeSystemService(object):
    def __init__(self, clusters, networks_by_cluster_id,
                 profiles_by_network_id):
        self._clusters = clusters
        self._networks_by_cluster_id = networks_by_cluster_id
        self._profiles_by_network_id = profiles_by_network_id

    def clusters_service(self):
        return _FakeClustersService(
            self._clusters, self._networks_by_cluster_id,
            self._profiles_by_network_id)

    def networks_service(self):
        return _FakeNetworksService([], self._profiles_by_network_id)


def _two_datacenter_engine():
    """The lane's real shape: two datacenters, two ovirtmgmt networks.

    engine-setup creates the Default datacenter and its ovirtmgmt;
    start-test-target.py creates the test datacenter with an ovirtmgmt
    of its own. Both networks, and both of their vNIC profiles, are
    named ovirtmgmt. The Default one is listed first, which is what
    made selection-by-name pick the wrong one.
    """
    return _FakeSystemService(
        clusters=[_Named('c-default', 'Default'), _Named('c-test', 'test')],
        networks_by_cluster_id={
            'c-default': [_Named('net-default', 'ovirtmgmt')],
            'c-test': [_Named('net-test', 'ovirtmgmt')],
        },
        profiles_by_network_id={
            'net-default': [_Named('profile-default', 'ovirtmgmt')],
            'net-test': [_Named('profile-test', 'ovirtmgmt')],
        })


class ResolveVnicProfileTestCase(testtools.TestCase):
    def test_picks_the_profile_from_the_target_clusters_datacenter(self):
        """The regression: two ovirtmgmt profiles, only one attachable.

        Selecting by name alone returned profile-default here, and the
        engine rejected it with HTTP 409 "The specified Logical Network
        doesn't exist in the current Cluster".
        """
        profile = create_ovirt_vnc_vm._resolve_vnic_profile(
            _two_datacenter_engine(), 'test', 'ovirtmgmt')
        self.assertEqual('profile-test', profile.id)

    def test_resolves_the_other_datacenter_too(self):
        """Nothing is hard coded to the test cluster."""
        profile = create_ovirt_vnc_vm._resolve_vnic_profile(
            _two_datacenter_engine(), 'Default', 'ovirtmgmt')
        self.assertEqual('profile-default', profile.id)

    def test_prefers_the_profile_sharing_the_network_name(self):
        system_service = _FakeSystemService(
            clusters=[_Named('c-test', 'test')],
            networks_by_cluster_id={
                'c-test': [_Named('net-test', 'ovirtmgmt')]},
            profiles_by_network_id={
                'net-test': [_Named('profile-other', 'passthrough'),
                             _Named('profile-mgmt', 'ovirtmgmt')]})

        profile = create_ovirt_vnc_vm._resolve_vnic_profile(
            system_service, 'test', 'ovirtmgmt')
        self.assertEqual('profile-mgmt', profile.id)

    def test_falls_back_to_any_profile_on_the_network(self):
        """A renamed profile is still attachable in this cluster."""
        system_service = _FakeSystemService(
            clusters=[_Named('c-test', 'test')],
            networks_by_cluster_id={
                'c-test': [_Named('net-test', 'ovirtmgmt')]},
            profiles_by_network_id={
                'net-test': [_Named('profile-renamed', 'mgmt-profile')]})

        profile = create_ovirt_vnc_vm._resolve_vnic_profile(
            system_service, 'test', 'ovirtmgmt')
        self.assertEqual('profile-renamed', profile.id)

    def test_unknown_cluster_names_what_was_available(self):
        error = self.assertRaises(
            SystemExit, create_ovirt_vnc_vm._resolve_vnic_profile,
            _two_datacenter_engine(), 'nonexistent', 'ovirtmgmt')
        self.assertIn('no cluster named nonexistent', str(error))
        self.assertIn('Default, test', str(error))

    def test_network_missing_from_cluster_is_reported_against_the_cluster(
            self):
        error = self.assertRaises(
            SystemExit, create_ovirt_vnc_vm._resolve_vnic_profile,
            _two_datacenter_engine(), 'test', 'nonexistent')
        self.assertIn('cluster test has no network named nonexistent',
                      str(error))
        self.assertIn('ovirtmgmt', str(error))

    def test_network_without_profiles_is_reported(self):
        system_service = _FakeSystemService(
            clusters=[_Named('c-test', 'test')],
            networks_by_cluster_id={
                'c-test': [_Named('net-test', 'ovirtmgmt')]},
            profiles_by_network_id={})

        error = self.assertRaises(
            SystemExit, create_ovirt_vnc_vm._resolve_vnic_profile,
            system_service, 'test', 'ovirtmgmt')
        self.assertIn('has no vNIC profiles', str(error))
