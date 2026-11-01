import os
import re
import requests
from shakenfist_utilities import logs
import tempfile
import time
import urllib.parse

from . import base
from .. import util


LOG, _ = logs.setup(__name__, **util.configure_logging())


# Seconds to wait for the PVE API to accept a connection, and then for each
# part of its response. requests applies this to the connect and to every gap
# between reads separately, not to a request as a whole, so an API answering
# slowly but steadily can take longer; what bounds a whole mint for the client
# waiting on it is minting.MINT_DEADLINE.
REQUEST_TIMEOUT = 5

# Seconds into a mint after which spiceproxy is no longer asked for a ticket.
# Asking sets the VM's SPICE password, so a mint whose first two requests were
# slow gives up rather than change the password for a client which may have
# stopped waiting. Ten seconds is MINT_DEADLINE (20) less two REQUEST_TIMEOUTs,
# so a POST sent in time normally answers before the caller gives up. It also
# leaves the ticket TICKET_LIFETIME - 10 = 20 seconds when the POST is sent,
# and still about 15 after a POST taking one REQUEST_TIMEOUT, more than the
# REUSE_MARGIN (10, kerbside/rpc/servicer.py) a stored ticket must have left
# for the session's other channels to reuse it rather than mint again at once.
# It counts from when this driver starts minting, not from when the caller
# began waiting, so time the caller spent queued behind an earlier mint of
# the same console is not counted: this narrows the window, not closes it.
MINT_POST_CUTOFF = 10

# Seconds a minted SPICE password is good for. spiceproxy sets the password
# and then runs mon_cmd($vmid, "expire_password", ..., time => "+30") on the
# VM's qemu (qemu-server src/PVE/API2/Qemu.pm), and has no parameter to ask
# for longer. The CONNECT ticket in the connect host is accepted for a few
# seconds more than this, so the password is what expires first.
TICKET_LIFETIME = 30

# The certificate qemu's SPICE listener presents on each node, as named by
# GET /nodes/{node}/certificates/info.
NODE_CERTIFICATE = 'pve-ssl.pem'

# A console's uuid is the VM's vmid and its SMBIOS UUID, joined by a '-'.
# PVE hands out the lowest free vmid, so a vmid alone would name a deleted
# VM and its successor alike; the SMBIOS UUID tells them apart, and the vmid
# lets a mint find the VM without reading every VM's config.
_CONSOLE_UUID = re.compile(
    r'^([1-9][0-9]*)-([0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})$')

# qemu-server starts qemu with -spice for these display types, and for no
# others: vga_conf_has_spice() matches qxl, qxl2, qxl3 and qxl4, and
# config_to_command() adds anything starting with virtio
# (src/PVE/QemuServer.pm). The default display, std, has no SPICE.
_SPICE_VGA_TYPE = re.compile(r'^(?:qxl[234]?$|virtio)')


# A node name as PVE accepts one, a single hostname label (pve-common's
# pve_verify_node_name(), the pve-node format). Node names come from the API
# and are put into API paths, so a guest on a node named otherwise is never
# asked about: a malformed or hostile guest list could otherwise steer a
# request, the spiceproxy POST included, to another path.
_NODE_NAME = re.compile(r'[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?')


class MalformedResponse(Exception):
    """A PVE API response did not carry its payload under 'data'."""


# The failures one request to the API can end in.
API_ERRORS = (requests.exceptions.RequestException, MalformedResponse)


def console_uuid(vmid, smbios_uuid):
    """The uuid of the console of a VM, from its vmid and SMBIOS UUID."""
    return '%d-%s' % (int(vmid), smbios_uuid.lower())


def parse_console_uuid(uuid):
    """Split a console's uuid into the VM's vmid and its SMBIOS UUID.

    Raises ConsoleTicketUnavailable for a uuid which console_uuid() could
    not have produced. The message does not quote the uuid.
    """
    m = _CONSOLE_UUID.match(uuid or '')
    if not m:
        raise base.ConsoleTicketUnavailable(
            'console uuid is not of the form <vmid>-<smbios uuid>')
    return int(m.group(1)), m.group(2)


def valid_node_name(node):
    """Whether node is a node name PVE would accept."""
    return isinstance(node, str) and bool(_NODE_NAME.fullmatch(node))


def _property_string(value, default_key=None):
    """Parse a PVE property string, such as 'qxl,memory=32', into a dict.

    Parts are comma separated key=value pairs, and a part without an '='
    is the value of the format's default key. Returns None for a string PVE
    would refuse, which has a key twice or a bare value with no default key
    to give it to (pve-common's parse_property_string()).
    """
    parsed = {}
    for part in (value or '').split(','):
        if not part.strip():
            continue
        key, sep, val = part.partition('=')
        if not sep:
            if not default_key:
                return None
            key, val = default_key, part
        if key in parsed:
            return None
        parsed[key] = val
    return parsed


def vga_has_spice(vga):
    """Whether qemu runs a SPICE server for a VM with this vga setting.

    vga is the VM's 'vga' config value, whose default key is the display
    type. A VM with no vga set has the default display, std.
    """
    parsed = _property_string(vga, default_key='type')
    if not parsed or not parsed.get('type'):
        return False
    return bool(_SPICE_VGA_TYPE.match(parsed['type']))


def smbios_uuid(smbios1):
    """The SMBIOS UUID in a VM's 'smbios1' config value, lower cased.

    Returns None for a VM which has none.
    """
    parsed = _property_string(smbios1)
    if not parsed or not parsed.get('uuid'):
        return None
    return parsed['uuid'].lower()


def spice_host_subject(oneline):
    """Convert an X509_NAME_oneline() subject into the form spiceproxy gives.

    certificates/info reports a subject as '/OU=.../O=.../CN=node.example'.
    The host-subject spiceproxy hands to SPICE clients drops the leading '/'
    and turns each '/' before an attribute into ',' (pve-access-control's
    read_x509_subject_spice()), and the backend leg is pinned against that.
    """
    subject = re.sub(r'^/', '', oneline)
    return re.sub(r'/(\w+=)', r',\1', subject)


def _failure(e):
    """Describe a failed request by its exception class and HTTP status.

    Never the exception's text: it can quote a URL, and a response body
    could quote anything.
    """
    response = getattr(e, 'response', None)
    return {
        'error': type(e).__name__,
        'status': getattr(response, 'status_code', None)
    }


class ProxmoxSource(base.BaseSource):
    MINTS_TICKETS = True

    # A ticket is good for TICKET_LIFETIME seconds, too short for a .vv file
    # to be downloaded and opened, and only kerbside can CONNECT for it.
    DIRECT_CONSOLES = False

    def __init__(self, **kwargs):
        self.args = kwargs
        self.errored = False
        self.ca_tempfile = None

        missing = [k for k in ('url', 'username', 'password', 'ca_cert')
                   if not self.args.get(k)]
        if missing:
            LOG.warning('Ignoring source %s as it is missing %s'
                        % (self.args.get('source'), ', '.join(missing)))
            self.errored = True
            return

        # spiceproxy is asked for a CONNECT proxy on the host the API is
        # reached on, as PVE recommends, so that kerbside dials a host it
        # already reaches rather than each node's FQDN. PVE brackets an
        # IPv6 address itself.
        url = urllib.parse.urlsplit(self.args['url'])
        self.proxy_host = url.hostname
        if not self.proxy_host:
            LOG.warning('Ignoring source %s as its url names no host'
                        % self.args.get('source'))
            self.errored = True
            return

        # Over http the token travels in the clear and requests never checks
        # the CA, so nothing but https is accepted.
        if url.scheme != 'https':
            LOG.warning('Ignoring source %s as its url is not https'
                        % self.args.get('source'))
            self.errored = True
            return

        self.api = self.args['url'].rstrip('/') + '/api2/json'
        self.headers = {
            'Authorization': 'PVEAPIToken=%s=%s'
            % (self.args['username'], self.args['password'])
        }

        # requests verifies against a CA bundle on disk. The cluster CA also
        # signs each node's certificate, which the backend leg is checked
        # against.
        fd, self.ca_tempfile = tempfile.mkstemp()
        os.close(fd)
        with open(self.ca_tempfile, 'w') as f:
            f.write(self.args['ca_cert'])

    def close(self):
        if self.ca_tempfile:
            os.unlink(self.ca_tempfile)
            self.ca_tempfile = None

    def _data(self, r):
        r.raise_for_status()
        body = r.json()
        if not isinstance(body, dict) or 'data' not in body:
            raise MalformedResponse('the response carried no data')
        return body['data']

    def _get(self, path, params=None):
        return self._data(requests.get(
            self.api + path, params=params, headers=self.headers,
            verify=self.ca_tempfile, timeout=REQUEST_TIMEOUT))

    def _post(self, path, data):
        return self._data(requests.post(
            self.api + path, data=data, headers=self.headers,
            verify=self.ca_tempfile, timeout=REQUEST_TIMEOUT))

    def _guests(self):
        # Every guest in the cluster with the node it is on, filtered by
        # the token's VM.Audit. status and template come from the node's
        # last status report, and are missing until it has made one.
        guests = self._get('/cluster/resources', params={'type': 'vm'})
        if not isinstance(guests, list):
            raise MalformedResponse('the guest list was not a list')
        return [g for g in guests if isinstance(g, dict)]

    def _config(self, node, vmid):
        # current=1 asks for the configuration the VM is running with, rather
        # than one with changes still pending.
        config = self._get('/nodes/%s/qemu/%d/config' % (node, vmid),
                           params={'current': 1})
        if not isinstance(config, dict):
            raise MalformedResponse('the VM configuration was not a mapping')
        return config

    def _node_subject(self, node):
        """The host subject of a node's SPICE certificate, or None.

        None means the node answered and has no such certificate. A request
        which fails is raised.
        """
        try:
            certificates = self._get('/nodes/%s/certificates/info' % node)
        except API_ERRORS as e:
            fields = dict(_failure(e), source=self.args['source'], node=node)
            LOG.with_fields(fields).warning('Could not list the certificates of a node')
            raise

        for certificate in certificates or []:
            if (isinstance(certificate, dict) and
                    certificate.get('filename') == NODE_CERTIFICATE and
                    certificate.get('subject')):
                return spice_host_subject(certificate['subject'])

        LOG.with_fields({'source': self.args['source'], 'node': node}).warning(
            'Ignoring consoles on a node with no %s subject' % NODE_CERTIFICATE)
        return None

    def __call__(self):
        if self.errored:
            LOG.warning('Ignoring source %s as it is not usable' % self.args.get('source'))
            return

        # A request which fails, for the guest list, a node's certificates or
        # one VM's configuration, is raised, so that the source is recorded
        # as errored and keeps every console it had. Finishing without a
        # console would instead remove it, and with it the tokens of any
        # session using it. Only a VM the API has described, and which cannot
        # be brokered, is skipped.
        subjects = {}
        for guest in self._guests():
            log = LOG.with_fields({
                'source': self.args['source'],
                'vmid': guest.get('vmid'),
                'node': guest.get('node'),
                'type': guest.get('type'),
                'status': guest.get('status')
                })

            if guest.get('type') != 'qemu':
                log.debug('Ignoring guest which is not a qemu VM')
                continue
            if guest.get('template'):
                log.debug('Ignoring VM template')
                continue
            if guest.get('status') != 'running':
                log.debug('Ignoring VM with incorrect status')
                continue

            node = guest.get('node')
            vmid = guest.get('vmid')
            if not node or not isinstance(vmid, int):
                log.debug('Ignoring VM with no node or vmid')
                continue
            if not valid_node_name(node):
                log.debug('Ignoring VM on a node whose name PVE would not accept')
                continue

            if node not in subjects:
                subjects[node] = self._node_subject(node)
            if not subjects[node]:
                continue

            try:
                config = self._config(node, vmid)
            except API_ERRORS as e:
                log.with_fields(_failure(e)).warning('Could not read the configuration of a VM')
                raise

            if not vga_has_spice(config.get('vga')):
                log.debug('Ignoring VM with no SPICE display')
                continue

            smbios = smbios_uuid(config.get('smbios1'))
            if not smbios:
                log.info('Ignoring VM with no SMBIOS UUID, which its console uuid needs')
                continue

            yield {
                'uuid': console_uuid(vmid, smbios),
                'source': self.args['source'],
                'hypervisor': node,
                'hypervisor_ip': '',
                'insecure_port': None,
                'secure_port': None,
                'name': '%s' % (config.get('name') or guest.get('name') or 'VM %d' % vmid),
                'host_subject': subjects[node]
            }

    def _unavailable(self, vmid, reason):
        LOG.with_fields({'source': self.args.get('source'), 'vmid': vmid}).warning(
            'Cannot mint a console ticket: %s' % reason)
        return base.ConsoleTicketUnavailable(
            'source %s VM %s: %s' % (self.args.get('source'), vmid, reason))

    def mint_console_ticket(self, uuid, lifetime):
        # lifetime is not sent: spiceproxy has no parameter for it, and its
        # password always expires TICKET_LIFETIME seconds after the mint.
        if self.errored:
            raise base.ConsoleTicketUnavailable(
                'source %s is not usable' % self.args.get('source'))
        vmid, smbios = parse_console_uuid(uuid)

        # The time is taken before the first request, so that the expiry
        # reported is never later than the one qemu applies.
        now = int(time.time())
        started = time.monotonic()
        step = 'listing guests'
        try:
            # The VM's current node, so that a VM which has migrated since
            # it was discovered still mints.
            guest = next(
                (g for g in self._guests()
                 if g.get('vmid') == vmid and g.get('type') == 'qemu'), None)
            if not guest or not guest.get('node'):
                raise self._unavailable(vmid, 'no such VM')
            if not valid_node_name(guest['node']):
                raise self._unavailable(vmid, 'VM is on a node whose name PVE would not accept')
            if guest.get('status') != 'running':
                raise self._unavailable(vmid, 'VM is not running')
            node = guest['node']

            # A vmid is reused once its VM is deleted, so check that this is
            # still the machine the console was discovered as before setting
            # its password.
            step = 'reading VM configuration'
            config = self._config(node, vmid)
            if smbios_uuid(config.get('smbios1')) != smbios:
                raise self._unavailable(vmid, 'VM is not the machine the console was discovered as')
            if not vga_has_spice(config.get('vga')):
                raise self._unavailable(vmid, 'VM has no SPICE display')

            # A mint which has taken too long already does not go on to
            # replace the VM's password; see MINT_POST_CUTOFF.
            if time.monotonic() - started > MINT_POST_CUTOFF:
                raise self._unavailable(vmid, 'the API was too slow to mint in time')

            # This sets the VM's SPICE password, so it is only ever called
            # here and never during discovery.
            step = 'minting'
            minted = self._post('/nodes/%s/qemu/%d/spiceproxy' % (node, vmid),
                                {'proxy': self.proxy_host})
        except API_ERRORS as e:
            LOG.with_fields(dict(_failure(e), source=self.args['source'], vmid=vmid, step=step)).warning(
                'Proxmox VE API request failed while minting a console ticket')
            raise

        # The response's ca is not used: the backend leg is checked against
        # the source's configured CA, not one the API chose.
        try:
            tunnel = base.Tunnel(minted['proxy'], minted['host'], int(minted['tls-port']))
            password = minted['password']
            proxy_host = urllib.parse.urlsplit(tunnel.proxy_uri).hostname
        except (KeyError, TypeError, ValueError, AttributeError):
            raise self._unavailable(vmid, 'spiceproxy returned an incomplete ticket')
        if not password:
            raise self._unavailable(vmid, 'spiceproxy returned an incomplete ticket')

        # The connect host crosses the CONNECT in plaintext, so it is only
        # ever sent to the proxy this mint asked for: the API's own host.
        # urlsplit() lowercases both hostnames.
        if proxy_host != self.proxy_host:
            raise self._unavailable(vmid, 'spiceproxy named a proxy other than the API host')
        return base.MintedTicket(password, now + TICKET_LIFETIME, tunnel)
