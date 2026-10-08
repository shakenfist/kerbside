# A static console source driver that reads its VM mapping from an
# inline 'consoles:' list in the sources.yaml entry.  No real
# hypervisor or control-plane is required.  This driver is designed
# for two use-cases:
#
#   1. CI pipelines that launch QEMU directly and need kerbside to
#      front it (see the direct-qemu CI lane).
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
# util.load_sources() reads every unquoted number exactly as written, so
# ticket: 012345 is the text "012345" rather than YAML 1.1's octal 5349,
# and a port quoted or not ("5910", 5910) is that port.  Any other type
# -- a list, a mapping, a bool, a port outside 1 to 65535 -- errors the
# source.
#
# Notes:
# - Tickets are persisted to the Console DB at enumeration time via
#   db.add_console(..., ticket=...).  No per-request driver
#   instantiation is needed at .vv-generation time.
# - The consoles list is re-read every 60 seconds by the maintenance
#   loop in main.py, and in both directions: an entry added to the
#   file is discovered, and one removed from it is deleted.  An
#   edited field of an existing entry, the ticket included, is
#   applied on the next pass and audit logged as 'Console
#   configuration changed' with the names of the changed fields.
# - Duplicate UUIDs within a single static source are tolerated with
#   a warning; the last definition wins.
# - Validation catches a malformed entry, or an absent or misspelled
#   consoles key, and errors the whole source, which retains what it
#   had published.  Only an explicitly empty list ('consoles: []')
#   means the source has no consoles, and deletes what it had.

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

# How each field is normalised to the type its database column stores.
# See util.yaml_string() for why this matters.
_NORMALISERS = {
    'uuid': util.yaml_string,
    'name': util.yaml_string,
    'hypervisor': util.yaml_string,
    'hypervisor_ip': util.yaml_string,
    'insecure_port': util.yaml_port,
    'ticket': util.yaml_string,
    'secure_port': util.yaml_port,
    'host_subject': util.yaml_string,
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
        # Absent is an error rather than an empty list. A source which
        # enumerates cleanly with nothing in it has every console it
        # had published deleted by the maintenance loop, so a deleted
        # or misspelled key must fail closed like a malformed entry
        # does. An operator who means "no consoles" writes the empty
        # list explicitly.
        if 'consoles' not in self.args:
            LOG.error(
                'Static source %s: no "consoles" key (keys present: %s); '
                'write "consoles: []" for a source with no consoles'
                % (source_name, sorted(self.args.keys())))
            self.errored = True
            return
        consoles = self.args['consoles']

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

            # Validate required fields. The entry itself is not logged:
            # it is a raw sources.yaml console entry, so an entry which
            # supplies 'ticket' but omits some other required field
            # would write the operator's SPICE password to the daemon
            # log. Naming the keys is what the operator needs to fix
            # the file, and the uuid (when present) says which entry.
            missing = [f for f in _REQUIRED_FIELDS if f not in entry]
            if missing:
                LOG.error(
                    'Static source %s: console entry missing required '
                    'fields: %s (entry uuid: %s, keys present: %s)'
                    % (source_name, missing, entry.get('uuid', '<absent>'),
                       sorted(entry.keys())))
                self.errored = True
                return

            console = {'source': source_name}
            for field in _REQUIRED_FIELDS:
                console[field] = entry[field]
            for field, default in _OPTIONAL_FIELDS.items():
                console[field] = entry.get(field, default)

            # Name the field and its type, never its value, which may be
            # the ticket.
            for field, normalise in _NORMALISERS.items():
                if field in _OPTIONAL_FIELDS and console[field] is None:
                    continue
                try:
                    console[field] = normalise(console[field])
                except util.YAMLScalarError as e:
                    LOG.error(
                        'Static source %s: console field %s %s '
                        '(entry uuid: %s)'
                        % (source_name, field, e,
                           console['uuid'] if field != 'uuid' else '<invalid>'))
                    self.errored = True
                    return

            uuid = console['uuid']
            if uuid in self._consoles_by_uuid:
                LOG.warning(
                    'Static source %s: duplicate uuid %s — '
                    'last definition wins' % (source_name, uuid))

            self._consoles_by_uuid[uuid] = console

    def __call__(self):
        for console in self._consoles_by_uuid.values():
            yield console

    # close() is inherited as a no-op stub from BaseSource.
