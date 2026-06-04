# A static console source driver that reads its VM mapping from an
# inline 'consoles:' list in the sources.yaml entry.  No real
# hypervisor or control-plane is required.  This driver is designed
# for two use-cases:
#
#   1. CI pipelines that launch QEMU directly and need kerbside to
#      front it (see the direct-qemu CI lane, phase 5 of the
#      test-harness plan).
#   2. Ad-hoc debugging sessions where you want to point kerbside at
#      a hand-rolled QEMU without spinning up a full control plane
#      first.
#
# sources.yaml shape for a static source:
#
#   - source: my-static-source
#     type: static
#     consoles:
#       - uuid: "6f4e2c1a-0000-0000-0000-000000000001"
#         name: "test-vm-1"
#         hypervisor: "localhost"
#         hypervisor_ip: "127.0.0.1"
#         insecure_port: 5910
#         ticket: "my-spice-password"
#         # Optional fields:
#         # secure_port: null
#         # host_subject: null
#
# Required fields per console entry:
#   uuid, name, hypervisor, hypervisor_ip, insecure_port, ticket
#
# Optional fields (default to None):
#   secure_port, host_subject
#
# Notes:
# - Tickets are persisted to the Console DB at enumeration time via
#   db.add_console(..., ticket=...).  No per-request driver
#   instantiation is needed at .vv-generation time.
# - Hot-reload is not supported.  Restart kerbside to pick up changes
#   to the consoles list.
# - Duplicate UUIDs within a single static source are tolerated with
#   a warning; the last definition wins.

from shakenfist_utilities import logs

from . import base
from .. import util


LOG, _ = logs.setup(__name__, **util.configure_logging())


# Required fields that every console entry must supply.
_REQUIRED_FIELDS = ('uuid', 'name', 'hypervisor', 'hypervisor_ip',
                    'insecure_port', 'ticket')

# Optional fields and their default values.
_OPTIONAL_FIELDS = {
    'secure_port': None,
    'host_subject': None,
}


class StaticSource(base.BaseSource):
    """Console source that reads its mapping from a static in-line list.

    Designed for CI pipelines and ad-hoc debugging.  No external API
    calls are made; all console data comes directly from the
    sources.yaml configuration.
    """

    def __init__(self, **kwargs):
        self.args = kwargs
        self.errored = False
        self._consoles_by_uuid = {}

        source_name = self.args.get('source', '<unknown>')
        consoles = self.args.get('consoles', [])

        if not isinstance(consoles, list):
            LOG.error(
                'Static source %s: "consoles" must be a list, got %s'
                % (source_name, type(consoles).__name__))
            self.errored = True
            return

        for entry in consoles:
            if not isinstance(entry, dict):
                LOG.error(
                    'Static source %s: each console entry must be a dict, '
                    'got %s' % (source_name, type(entry).__name__))
                self.errored = True
                return

            # Validate required fields.
            missing = [f for f in _REQUIRED_FIELDS if f not in entry]
            if missing:
                LOG.error(
                    'Static source %s: console entry missing required '
                    'fields: %s (entry: %s)'
                    % (source_name, missing, entry))
                self.errored = True
                return

            uuid = entry['uuid']
            if uuid in self._consoles_by_uuid:
                LOG.warning(
                    'Static source %s: duplicate uuid %s — '
                    'last definition wins' % (source_name, uuid))

            console = {
                'uuid': uuid,
                'source': source_name,
                'name': entry['name'],
                'hypervisor': entry['hypervisor'],
                'hypervisor_ip': entry['hypervisor_ip'],
                'insecure_port': entry['insecure_port'],
                'ticket': entry['ticket'],
            }
            for field, default in _OPTIONAL_FIELDS.items():
                console[field] = entry.get(field, default)

            self._consoles_by_uuid[uuid] = console

    def __call__(self):
        for console in self._consoles_by_uuid.values():
            yield console

    # close() is inherited as a no-op stub from BaseSource.
