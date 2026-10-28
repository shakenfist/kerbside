import logging
import os
import unittest
from unittest import mock

import requests

from kerbside import sources
from kerbside.rpc import servicer
from kerbside.sources import base
from kerbside.sources import minting
from kerbside.sources import proxmox


URL = 'https://pve1.example:8006'
API = URL + '/api2/json'
TOKEN_ID = 'kerbside@pve!broker'

# Values which must never reach a log record. Each is distinctive enough
# that finding it anywhere in a captured record is a leak.
SECRET = 'sentinel-token-secret-7c1e5a'
PASSWORD = 'sentinel-spice-password-91ab0f'
CONNECT_HOST = 'pvespiceproxy:sentinel-connect-host-4d2f:100:pve1:61000::0ce019e3c7'

SMBIOS = '3f0c9a52-1b7e-4d8a-9c2f-5e6d7a8b9c0d'
OTHER_SMBIOS = '9b1d2e3f-4a5b-4c6d-8e7f-0a1b2c3d4e5f'
CA_CERT = '-----BEGIN CERTIFICATE-----\nCLUSTERCA\n-----END CERTIFICATE-----\n'

# The node certificate's subject as GET /nodes/{node}/certificates/info
# reports it, in X509_NAME_oneline() form (pve-common
# src/PVE/Certificate.pm, get_certificate_info()), and as spiceproxy's
# host-subject gave it for the same certificate when measured against a
# PVE 9.2 node.
ONELINE_SUBJECT = '/OU=PVE Cluster Node/O=Proxmox Virtual Environment/CN=pve1.example'
MEASURED_SUBJECT = 'OU=PVE Cluster Node,O=Proxmox Virtual Environment,CN=pve1.example'


def _guest(vmid=100, node='pve1', type='qemu', status='running', template=0,
           name='desktop-1'):
    """One entry of GET /cluster/resources?type=vm.

    Shaped by pve-manager's extract_vm_stats() (PVE/API2Tools.pm): vmid is
    a number, and name, status and template come from the node's status
    report.
    """
    return {
        'id': '%s/%d' % (type, vmid),
        'vmid': vmid,
        'node': node,
        'type': type,
        'status': status,
        'template': template,
        'name': name,
        'uptime': 1234,
        'maxcpu': 2,
        'maxmem': 2147483648,
    }


def _config(vga='qxl', smbios1='uuid=%s' % SMBIOS, name='desktop-1'):
    """GET /nodes/{node}/qemu/{vmid}/config?current=1, as qemu-server
    returns it: config values as written in the VM's config file, so vga
    and smbios1 are property strings. A key left as None is absent."""
    config = {
        'name': name,
        'vga': vga,
        'smbios1': smbios1,
        'memory': '2048',
        'cores': 2,
        'ostype': 'l26',
        'digest': 'a3f1c0ffee',
    }
    return {k: v for k, v in config.items() if v is not None}


def _certificates(subject=ONELINE_SUBJECT):
    """GET /nodes/{node}/certificates/info: the cluster CA, the node's
    certificate and, when one is installed, pveproxy's (pve-manager
    PVE/API2/Certificates.pm). filename is the base name only."""
    return [
        {'filename': 'pve-root-ca.pem',
         'subject': '/CN=Proxmox Virtual Environment/OU=c0ffee/O=PVE Cluster Manager CA',
         'fingerprint': 'AA:BB'},
        {'filename': 'pve-ssl.pem', 'subject': subject, 'fingerprint': 'CC:DD',
         'san': ['127.0.0.1', 'localhost', 'pve1', 'pve1.example']},
    ]


def _spiceproxy(**overrides):
    """POST /nodes/{node}/qemu/{vmid}/spiceproxy, as measured: the ca has
    its newlines escaped for a .vv file."""
    minted = {
        'type': 'spice',
        'proxy': 'http://pve1.example:3128',
        'host': CONNECT_HOST,
        'tls-port': 61000,
        'password': PASSWORD,
        'host-subject': MEASURED_SUBJECT,
        'ca': CA_CERT.replace('\n', '\\n'),
        'title': 'VM 100 - desktop-1',
        'delete-this-file': 1,
    }
    minted.update(overrides)
    return {k: v for k, v in minted.items() if v is not None}


class _Response(object):
    """Enough of a requests.Response. Every PVE API response wraps its
    payload in {"data": ...}."""

    def __init__(self, data=None, status=200, body=None):
        self.status_code = status
        self.body = {'data': data} if body is None else body

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.exceptions.HTTPError(
                '%d Server Error' % self.status_code, response=self)

    def json(self):
        return self.body


class _Slow(object):
    """An answer which takes seconds longer than a request usually does."""

    def __init__(self, seconds, answer):
        self.seconds = seconds
        self.answer = answer


class _FakePve(object):
    """Answers the driver's requests by method and API path.

    Every request is recorded with its keyword arguments, and advances a
    clock by a second, or by more for a _Slow answer, so that a test can
    tell when the driver read the time relative to its requests. A request
    with no answer fails the test.
    """

    def __init__(self, answers):
        self.answers = answers
        self.calls = []
        self.clock = 1700000000.75

    def time(self):
        return self.clock

    def get(self, url, **kwargs):
        return self._answer('GET', url, kwargs)

    def post(self, url, **kwargs):
        return self._answer('POST', url, kwargs)

    def _answer(self, method, url, kwargs):
        self.clock += 1
        self.calls.append((method, url, kwargs))
        try:
            answer = self.answers[(method, url)]
        except KeyError:
            raise AssertionError('unexpected request %s %s' % (method, url))
        if isinstance(answer, _Slow):
            self.clock += answer.seconds
            answer = answer.answer
        if isinstance(answer, Exception):
            raise answer
        return answer

    def paths(self):
        return [(method, url[len(API):]) for method, url, _ in self.calls]


def _answers(guests=None, configs=None, certificates=None, spiceproxy=None):
    """The default answers for a node pve1 running VM 100."""
    if guests is None:
        guests = [_guest()]
    answers = {
        ('GET', API + '/cluster/resources'): _Response(guests),
        ('GET', API + '/nodes/pve1/certificates/info'): _Response(
            _certificates() if certificates is None else certificates),
        ('POST', API + '/nodes/pve1/qemu/100/spiceproxy'): _Response(
            _spiceproxy() if spiceproxy is None else spiceproxy),
    }
    for vmid, config in (configs or {100: _config()}).items():
        answers[('GET', API + '/nodes/pve1/qemu/%d/config' % vmid)] = (
            config if isinstance(config, Exception) else _Response(config))
    return answers


def _make_source(url=URL, **overrides):
    kwargs = {
        'source': 'test-proxmox', 'type': 'proxmox', 'url': url,
        'username': TOKEN_ID, 'password': SECRET, 'ca_cert': CA_CERT,
    }
    kwargs.update(overrides)
    src = proxmox.ProxmoxSource(**kwargs)
    return src


class _ProxmoxTestCase(unittest.TestCase):
    def _source(self, url=URL, **overrides):
        src = _make_source(url=url, **overrides)
        self.addCleanup(src.close)
        return src

    def _fake(self, answers=None):
        fake = _FakePve(_answers() if answers is None else answers)
        for name in ('get', 'post'):
            patcher = mock.patch.object(proxmox.requests, name, side_effect=getattr(fake, name))
            patcher.start()
            self.addCleanup(patcher.stop)
        for name in ('time', 'monotonic'):
            patcher = mock.patch.object(proxmox.time, name, side_effect=fake.time)
            patcher.start()
            self.addCleanup(patcher.stop)
        return fake

    def _scrape(self, answers=None, src=None):
        fake = self._fake(answers)
        return list((src or self._source())()), fake

    def _mint(self, uuid=None, answers=None, src=None, lifetime=90):
        fake = self._fake(answers)
        if uuid is None:
            uuid = proxmox.console_uuid(100, SMBIOS)
        return (src or self._source()).mint_console_ticket(uuid, lifetime), fake

    def _capture_logs(self):
        """Capture every log record emitted while the test runs, as its
        rendered message and every attribute it carries, structured fields
        included. The handler is on the root logger, so it sees them all."""
        records = []

        class Capture(logging.Handler):
            def emit(self, record):
                records.append(record.getMessage())
                records.append(repr(vars(record)))

        handler = Capture(level=logging.DEBUG)
        root = logging.getLogger()
        root.addHandler(handler)
        self.addCleanup(root.removeHandler, handler)
        self.addCleanup(root.setLevel, root.level)
        root.setLevel(logging.DEBUG)
        return records


class TestHelpers(unittest.TestCase):
    def test_subject_conversion_on_the_measured_subject(self):
        self.assertEqual(MEASURED_SUBJECT, proxmox.spice_host_subject(ONELINE_SUBJECT))

    def test_subject_conversion_keeps_a_slash_inside_a_value(self):
        # read_x509_subject_spice() only replaces a '/' which starts an
        # attribute.
        self.assertEqual('O=a/b c,CN=pve1', proxmox.spice_host_subject('/O=a/b c/CN=pve1'))

    def test_console_uuid_round_trips(self):
        uuid = proxmox.console_uuid(100, SMBIOS.upper())
        self.assertEqual('100-%s' % SMBIOS, uuid)
        self.assertEqual((100, SMBIOS), proxmox.parse_console_uuid(uuid))

    def test_parse_console_uuid_refuses_other_shapes(self):
        for uuid in ('', None, '100', SMBIOS, 'abc-%s' % SMBIOS, '0100-%s' % SMBIOS,
                     '-%s' % SMBIOS, '100-not-a-uuid', '100-%s' % SMBIOS.upper(),
                     '100-%s-extra' % SMBIOS, '100_%s' % SMBIOS, ' 100-%s' % SMBIOS):
            with self.assertRaises(base.ConsoleTicketUnavailable, msg=repr(uuid)) as cm:
                proxmox.parse_console_uuid(uuid)
            self.assertNotIn(SMBIOS, str(cm.exception))

    def test_vga_with_spice(self):
        # qemu-server's vga_conf_has_spice() and config_to_command(), with
        # the display type as the property string's default key.
        for vga in ('qxl', 'qxl2', 'qxl3', 'qxl4', 'virtio', 'virtio-gl',
                    'qxl,memory=32', 'memory=32,qxl', 'type=qxl2', 'virtio,memory=32,clipboard=vnc'):
            self.assertTrue(proxmox.vga_has_spice(vga), vga)

    def test_vga_without_spice(self):
        for vga in (None, '', 'std', 'cirrus', 'vmware', 'none', 'serial0', 'qxl5',
                    'std,clipboard=vnc', 'memory=32', 'qxl,qxl', 'qxl,type=qxl', 'xqxl'):
            self.assertFalse(proxmox.vga_has_spice(vga), vga)

    def test_smbios_uuid(self):
        self.assertEqual(SMBIOS, proxmox.smbios_uuid('uuid=%s' % SMBIOS))
        self.assertEqual(SMBIOS, proxmox.smbios_uuid(
            'base64=1,manufacturer=UVVFTVU=,uuid=%s' % SMBIOS.upper()))
        for smbios1 in (None, '', 'manufacturer=QEMU', 'uuid=', SMBIOS):
            self.assertIsNone(proxmox.smbios_uuid(smbios1), smbios1)


class TestConstruction(_ProxmoxTestCase):
    def test_registered(self):
        self.assertIs(proxmox.ProxmoxSource, sources.driver_class('proxmox'))

    def test_mints_and_offers_no_direct_consoles(self):
        self.assertTrue(proxmox.ProxmoxSource.MINTS_TICKETS)
        self.assertFalse(proxmox.ProxmoxSource.DIRECT_CONSOLES)

    def test_ca_cert_is_written_to_a_file_removed_by_close(self):
        src = _make_source()
        self.assertFalse(src.errored)
        with open(src.ca_tempfile) as f:
            self.assertEqual(CA_CERT, f.read())
        path = src.ca_tempfile

        src.close()
        self.assertFalse(os.path.exists(path))
        src.close()

    def test_built_as_a_mint_builds_it(self):
        # minting.mint_with_deadline() builds a driver from the source's
        # database row, with 'source' added.
        src = self._source(name='test-proxmox', errored=False, deleted=False,
                           project_name=None, user_domain_id=None, project_domain_id=None)
        self.assertFalse(src.errored)

    def test_missing_fields_mark_the_source_errored(self):
        for field in ('url', 'username', 'password', 'ca_cert'):
            records = self._capture_logs()
            src = self._source(**{field: None})
            self.assertTrue(src.errored, field)
            self.assertIsNone(src.ca_tempfile)
            self.assertNotIn(SECRET, '\n'.join(records))

    def test_url_with_no_host_marks_the_source_errored(self):
        self.assertTrue(self._source(url='pve1.example:8006').errored)

    def test_api_base_tolerates_a_trailing_slash(self):
        self.assertEqual(API, self._source(url=URL + '/').api)


class TestDiscovery(_ProxmoxTestCase):
    def test_running_spice_vm_is_yielded(self):
        results, fake = self._scrape()

        self.assertEqual(
            [{
                'uuid': '100-%s' % SMBIOS,
                'source': 'test-proxmox',
                'hypervisor': 'pve1',
                'hypervisor_ip': '',
                'insecure_port': None,
                'secure_port': None,
                'name': 'desktop-1',
                'host_subject': MEASURED_SUBJECT,
            }],
            results)
        self.assertEqual(
            [('GET', '/cluster/resources'),
             ('GET', '/nodes/pve1/certificates/info'),
             ('GET', '/nodes/pve1/qemu/100/config')],
            fake.paths())
        self.assertEqual({'type': 'vm'}, fake.calls[0][2]['params'])
        self.assertEqual({'current': 1}, fake.calls[2][2]['params'])

    def test_vms_which_cannot_be_brokered_are_skipped(self):
        guests = [
            _guest(100),
            _guest(101, status='stopped'),
            _guest(102, template=1),
            _guest(103, type='lxc'),
            _guest(104),
            _guest(105),
            _guest(106),
            _guest(107, status='unknown', name=None, template=None),
            _guest(108),
        ]
        configs = {
            100: _config(),
            104: _config(vga='std', smbios1='uuid=%s' % OTHER_SMBIOS),
            105: _config(vga=None, smbios1='uuid=%s' % OTHER_SMBIOS),
            106: _config(smbios1=None),
            108: _config(vga='virtio,memory=32', smbios1='uuid=%s' % OTHER_SMBIOS,
                         name='desktop-2'),
        }

        results, fake = self._scrape(_answers(guests=guests, configs=configs))

        self.assertEqual(
            ['100-%s' % SMBIOS, '108-%s' % OTHER_SMBIOS],
            [r['uuid'] for r in results])
        # Only candidates have their config read.
        self.assertEqual(
            ['/nodes/pve1/qemu/%d/config' % vmid for vmid in (100, 104, 105, 106, 108)],
            [path for _, path in fake.paths() if path.endswith('/config')])

    def test_vm_on_a_node_pve_would_not_name_is_skipped(self):
        """A node name goes into API paths, so one which could steer a
        request elsewhere is never asked about."""
        for node in ('../access', 'pve1/qemu', 'pve1.example', '-pve1', 'pve1-', '', 7):
            guests = [_guest(100), _guest(200, node=node)]
            records = []
            with mock.patch.object(proxmox.LOG, 'with_fields') as with_fields:
                with_fields.return_value.debug.side_effect = records.append
                results, fake = self._scrape(_answers(guests=guests))

            self.assertEqual(['100-%s' % SMBIOS], [r['uuid'] for r in results], node)
            self.assertEqual(
                [('GET', '/cluster/resources'),
                 ('GET', '/nodes/pve1/certificates/info'),
                 ('GET', '/nodes/pve1/qemu/100/config')],
                fake.paths(), node)
            self.assertEqual(1, len(records), node)

    def test_node_names_pve_accepts(self):
        for node in ('pve1', 'PVE-node-2', 'a', '9'):
            self.assertTrue(proxmox.valid_node_name(node), node)
        for node in ('../access', 'a/b', 'a.b', '-a', 'a-', 'a_b', 'a\n', '', None, 7):
            self.assertFalse(proxmox.valid_node_name(node), node)

    def test_vm_with_no_smbios_uuid_is_logged_at_info(self):
        records = []
        with mock.patch.object(proxmox.LOG, 'with_fields') as with_fields:
            with_fields.return_value.info.side_effect = records.append
            self._scrape(_answers(configs={100: _config(smbios1='manufacturer=QEMU')}))
        self.assertEqual(1, len(records))
        self.assertIn('SMBIOS', records[0])
        self.assertEqual(100, with_fields.call_args_list[0].args[0]['vmid'])

    def test_name_falls_back_to_the_guest_list_then_the_vmid(self):
        guests = [_guest(100, name='listed'), _guest(101, name=None)]
        configs = {100: _config(name=None), 101: _config(name=None, smbios1='uuid=%s' % OTHER_SMBIOS)}
        results, _ = self._scrape(_answers(guests=guests, configs=configs))
        self.assertEqual(['listed', 'VM 101'], [r['name'] for r in results])

    def test_subject_is_read_once_per_node(self):
        guests = [_guest(100), _guest(101), _guest(200, node='pve2')]
        answers = _answers(guests=guests, configs={
            100: _config(), 101: _config(smbios1='uuid=%s' % OTHER_SMBIOS)})
        answers[('GET', API + '/nodes/pve2/certificates/info')] = _Response(
            _certificates(subject='/OU=PVE Cluster Node/O=Proxmox Virtual Environment/CN=pve2.example'))
        answers[('GET', API + '/nodes/pve2/qemu/200/config')] = _Response(
            _config(smbios1='uuid=11111111-2222-3333-4444-555555555555'))

        results, fake = self._scrape(answers)

        self.assertEqual(
            [('pve1', MEASURED_SUBJECT), ('pve1', MEASURED_SUBJECT),
             ('pve2', 'OU=PVE Cluster Node,O=Proxmox Virtual Environment,CN=pve2.example')],
            [(r['hypervisor'], r['host_subject']) for r in results])
        self.assertEqual(
            ['/nodes/pve1/certificates/info', '/nodes/pve2/certificates/info'],
            [path for _, path in fake.paths() if path.endswith('/certificates/info')])

    def test_node_with_no_spice_certificate_yields_nothing(self):
        guests = [_guest(100), _guest(200, node='pve2')]
        answers = _answers(guests=guests)
        answers[('GET', API + '/nodes/pve2/certificates/info')] = _Response(_certificates()[:1])

        results, fake = self._scrape(answers)

        self.assertEqual(['pve1'], [r['hypervisor'] for r in results])
        self.assertNotIn(('GET', '/nodes/pve2/qemu/200/config'), fake.paths())

    def test_a_node_whose_certificates_cannot_be_read_is_raised(self):
        """Rather than finish without that node's consoles, which would
        remove them and the tokens of every session using them."""
        guests = [_guest(100), _guest(200, node='pve2')]
        for failure, raised in (
                (requests.exceptions.HTTPError('595 no route', response=_Response(status=595)),
                 requests.exceptions.HTTPError),
                (requests.exceptions.ConnectTimeout('timed out'), requests.exceptions.ConnectTimeout),
                (_Response(body={'errors': 'nope'}), proxmox.MalformedResponse)):
            answers = _answers(guests=guests)
            answers[('GET', API + '/nodes/pve2/certificates/info')] = failure
            with self.assertRaises(raised):
                self._scrape(answers)

    def test_a_vm_whose_config_cannot_be_read_is_raised(self):
        guests = [_guest(100), _guest(101)]
        configs = {
            100: _config(),
            101: requests.exceptions.HTTPError('500', response=_Response(status=500)),
        }
        with self.assertRaises(requests.exceptions.HTTPError):
            self._scrape(_answers(guests=guests, configs=configs))

    def test_a_failed_guest_list_is_raised(self):
        """So that the source is marked errored and its consoles are kept."""
        answers = _answers()
        answers[('GET', API + '/cluster/resources')] = _Response(status=401)
        with self.assertRaises(requests.exceptions.HTTPError):
            self._scrape(answers)

    def test_a_malformed_guest_list_is_raised(self):
        """Rather than read as a cluster with no VMs, whose consoles would
        all be removed."""
        for body in ({'errors': 'nope'}, {'data': {'vmid': 100}}, {'data': None}):
            answers = _answers()
            answers[('GET', API + '/cluster/resources')] = _Response(body=body)
            with self.assertRaises(proxmox.MalformedResponse):
                self._scrape(answers)

    def test_a_malformed_config_is_raised(self):
        guests = [_guest(100), _guest(101)]
        configs = {100: _config(), 101: _config(smbios1='uuid=%s' % OTHER_SMBIOS)}
        answers = _answers(guests=guests, configs=configs)
        answers[('GET', API + '/nodes/pve1/qemu/100/config')] = _Response(['vga', 'qxl'])
        with self.assertRaises(proxmox.MalformedResponse):
            self._scrape(answers)

    def test_discovery_never_posts(self):
        guests = [_guest(100), _guest(101, status='stopped'), _guest(102, type='lxc')]
        _, fake = self._scrape(_answers(guests=guests))
        self.assertEqual(['GET'], sorted(set(method for method, _ in fake.paths())))
        proxmox.requests.post.assert_not_called()

    def test_errored_source_discovers_nothing(self):
        src = self._source(password=None)
        results, fake = self._scrape(src=src)
        self.assertEqual([], results)
        self.assertEqual([], fake.calls)


class TestMinting(_ProxmoxTestCase):
    def test_mint_makes_three_requests_in_order(self):
        minted, fake = self._mint(lifetime=7777)

        self.assertEqual(
            [('GET', '/cluster/resources'),
             ('GET', '/nodes/pve1/qemu/100/config'),
             ('POST', '/nodes/pve1/qemu/100/spiceproxy')],
            fake.paths())
        self.assertEqual({'type': 'vm'}, fake.calls[0][2]['params'])
        self.assertEqual({'current': 1}, fake.calls[1][2]['params'])
        self.assertEqual({'proxy': 'pve1.example'}, fake.calls[2][2]['data'])
        # The lifetime asked for cannot be honoured, and is not sent.
        self.assertNotIn('7777', repr(fake.calls))

    def test_mint_returns_the_password_and_tunnel(self):
        minted, _ = self._mint()

        self.assertIsInstance(minted, base.MintedTicket)
        self.assertEqual(PASSWORD, minted.ticket)
        self.assertEqual(
            base.Tunnel('http://pve1.example:3128', CONNECT_HOST, 61000), minted.tunnel)
        self.assertTrue(base.tunnel_complete(minted.tunnel))

    def test_expiry_counts_from_before_the_first_request(self):
        fake_start = _FakePve({}).clock
        minted, fake = self._mint()

        # The fake clock advances a second per request, so a time read after
        # any of them would give a later expiry.
        self.assertEqual(3, len(fake.calls))
        self.assertEqual(int(fake_start) + proxmox.TICKET_LIFETIME, minted.expires)
        self.assertEqual(30, proxmox.TICKET_LIFETIME)

    def test_proxy_is_the_host_of_the_source_url(self):
        for url, host in ((URL, 'pve1.example'),
                          (URL + '/', 'pve1.example'),
                          ('https://PVE1.example', 'pve1.example'),
                          ('https://[fd00::1]:8006', 'fd00::1')):
            base_url = url.rstrip('/') + '/api2/json'
            answers = {(method, base_url + path[len(API):]): answer
                       for (method, path), answer in _answers().items()}
            minted, fake = self._mint(answers=answers, src=self._source(url=url))
            self.assertEqual({'proxy': host}, fake.calls[-1][2]['data'], url)

    def test_tls_port_as_a_string_is_an_integer(self):
        minted, _ = self._mint(answers=_answers(spiceproxy=_spiceproxy(**{'tls-port': '61000'})))
        self.assertEqual(61000, minted.tunnel.port)

    def test_vm_which_migrated_mints_on_its_new_node(self):
        answers = {
            ('GET', API + '/cluster/resources'): _Response([_guest(100, node='pve2')]),
            ('GET', API + '/nodes/pve2/qemu/100/config'): _Response(_config()),
            ('POST', API + '/nodes/pve2/qemu/100/spiceproxy'): _Response(_spiceproxy()),
        }
        minted, fake = self._mint(answers=answers)
        self.assertEqual(PASSWORD, minted.ticket)
        self.assertEqual(('POST', '/nodes/pve2/qemu/100/spiceproxy'), fake.paths()[-1])

    def _refused(self, answers=None, uuid=None, src=None):
        fake = self._fake(answers if answers is not None else _answers())
        if uuid is None:
            uuid = proxmox.console_uuid(100, SMBIOS)
        with self.assertRaises(base.ConsoleTicketUnavailable) as cm:
            (src or self._source()).mint_console_ticket(uuid, 90)
        self.assertNotIn(SMBIOS, str(cm.exception))
        self.assertNotIn(SECRET, str(cm.exception))
        return cm.exception, fake

    def test_smbios_mismatch_refuses_before_spiceproxy(self):
        """A vmid reused by a new VM is not the console's machine."""
        error, fake = self._refused(answers=_answers(
            configs={100: _config(smbios1='uuid=%s' % OTHER_SMBIOS)}))

        self.assertIn('100', str(error))
        self.assertNotIn(OTHER_SMBIOS, str(error))
        self.assertEqual(
            [('GET', '/cluster/resources'), ('GET', '/nodes/pve1/qemu/100/config')],
            fake.paths())
        proxmox.requests.post.assert_not_called()

    def test_vm_with_no_smbios_uuid_is_refused(self):
        _, fake = self._refused(answers=_answers(configs={100: _config(smbios1=None)}))
        proxmox.requests.post.assert_not_called()

    def test_vm_which_is_not_running_is_refused(self):
        for status in ('stopped', 'paused', 'unknown'):
            error, fake = self._refused(answers=_answers(guests=[_guest(status=status)]))
            self.assertIn('100', str(error))
            self.assertEqual([('GET', '/cluster/resources')], fake.paths())

    def test_vm_which_is_missing_is_refused(self):
        for guests in ([], [_guest(101)], [_guest(100, type='lxc')], [_guest(100, node=None)]):
            error, fake = self._refused(answers=_answers(guests=guests))
            self.assertIn('100', str(error))
            self.assertEqual([('GET', '/cluster/resources')], fake.paths())

    def test_vm_on_a_node_pve_would_not_name_is_refused(self):
        for node in ('../access', 'pve1/qemu', 'pve1.example', 7):
            error, fake = self._refused(answers=_answers(guests=[_guest(node=node)]))
            self.assertIn('100', str(error))
            self.assertIn('node', str(error))
            self.assertEqual([('GET', '/cluster/resources')], fake.paths())

    def test_slow_requests_end_the_mint_before_spiceproxy(self):
        """A mint which has run past MINT_POST_CUTOFF does not replace the
        VM's password for a caller which may have stopped waiting."""
        answers = _answers()
        answers[('GET', API + '/nodes/pve1/qemu/100/config')] = _Slow(
            proxmox.MINT_POST_CUTOFF, answers[('GET', API + '/nodes/pve1/qemu/100/config')])

        error, fake = self._refused(answers=answers)

        self.assertIn('100', str(error))
        self.assertEqual(
            [('GET', '/cluster/resources'), ('GET', '/nodes/pve1/qemu/100/config')],
            fake.paths())
        proxmox.requests.post.assert_not_called()

    def test_requests_inside_the_cutoff_still_mint(self):
        # Two requests at a second each, plus this, end exactly at the cutoff.
        answers = _answers()
        answers[('GET', API + '/nodes/pve1/qemu/100/config')] = _Slow(
            proxmox.MINT_POST_CUTOFF - 2, answers[('GET', API + '/nodes/pve1/qemu/100/config')])

        minted, fake = self._mint(answers=answers)

        self.assertEqual(PASSWORD, minted.ticket)
        self.assertEqual(('POST', '/nodes/pve1/qemu/100/spiceproxy'), fake.paths()[-1])

    def test_cutoff_leaves_a_ticket_worth_reusing(self):
        # A ticket posted for at the cutoff, whose POST takes a whole
        # REQUEST_TIMEOUT, still outlives the reuse margin, and the POST
        # answers before the caller's deadline.
        self.assertGreater(
            proxmox.TICKET_LIFETIME - proxmox.MINT_POST_CUTOFF - proxmox.REQUEST_TIMEOUT,
            servicer.REUSE_MARGIN)
        self.assertLess(proxmox.MINT_POST_CUTOFF + proxmox.REQUEST_TIMEOUT, minting.MINT_DEADLINE)

    def test_vm_with_no_spice_display_is_refused(self):
        self._refused(answers=_answers(configs={100: _config(vga='std')}))
        proxmox.requests.post.assert_not_called()

    def test_malformed_uuid_is_refused_without_a_request(self):
        _, fake = self._refused(uuid='100')
        self.assertEqual([], fake.calls)

    def test_errored_source_is_refused_without_a_request(self):
        _, fake = self._refused(src=self._source(ca_cert=None))
        self.assertEqual([], fake.calls)

    def test_incomplete_spiceproxy_response_is_refused(self):
        for missing in ('password', 'host', 'proxy', 'tls-port'):
            self._refused(answers=_answers(spiceproxy=_spiceproxy(**{missing: None})))
        self._refused(answers=_answers(spiceproxy=_spiceproxy(password='')))
        self._refused(answers=_answers(spiceproxy=_spiceproxy(**{'tls-port': 'none'})))

    def test_api_failures_are_raised(self):
        for path in ('/cluster/resources', '/nodes/pve1/qemu/100/config'):
            answers = _answers()
            answers[('GET', API + path)] = _Response(status=500)
            with self.assertRaises(requests.exceptions.HTTPError):
                self._mint(answers=answers)
        answers = _answers()
        answers[('POST', API + '/nodes/pve1/qemu/100/spiceproxy')] = requests.exceptions.ReadTimeout()
        with self.assertRaises(requests.exceptions.ReadTimeout):
            self._mint(answers=answers)


class TestEveryRequest(_ProxmoxTestCase):
    """Every request is bounded, authenticated by the token and verified
    against the source's CA, on discovery and minting alike."""

    def setUp(self):
        super().setUp()
        # Discovery reads a good node's subject, then a failing one's, which
        # ends the scrape.
        guests = [_guest(100), _guest(101, status='stopped'), _guest(200, node='pve2')]
        answers = _answers(guests=guests)
        answers[('GET', API + '/nodes/pve2/certificates/info')] = _Response(status=500)
        self._fake(answers)

    def test_every_request_carries_timeout_token_and_ca(self):
        src = self._source()
        with self.assertRaises(requests.exceptions.HTTPError):
            list(src())
        discovery = len(proxmox.requests.get.call_args_list)
        src.mint_console_ticket(proxmox.console_uuid(100, SMBIOS), 90)
        calls = proxmox.requests.get.call_args_list + proxmox.requests.post.call_args_list

        self.assertEqual(4, discovery)
        self.assertEqual(7, len(calls))
        for call in calls:
            self.assertEqual(proxmox.REQUEST_TIMEOUT, call.kwargs.get('timeout'), call)
            self.assertEqual(
                {'Authorization': 'PVEAPIToken=%s=%s' % (TOKEN_ID, SECRET)},
                call.kwargs.get('headers'))
            self.assertEqual(src.ca_tempfile, call.kwargs.get('verify'))
        self.assertEqual(5, proxmox.REQUEST_TIMEOUT)


class TestNothingSecretIsLogged(_ProxmoxTestCase):
    """The token secret, the SPICE password and the connect host reach no
    log record, whether a request succeeds or fails."""

    SENTINELS = (SECRET, PASSWORD, CONNECT_HOST, 'sentinel-')

    def _assert_clean(self, records):
        logged = '\n'.join(records)
        for sentinel in self.SENTINELS:
            self.assertNotIn(sentinel, logged)
        return logged

    def _leaky(self, cls, status=None):
        """A requests exception whose text quotes every sentinel."""
        text = 'failed with %s %s %s' % (SECRET, PASSWORD, CONNECT_HOST)
        if status is None:
            return cls(text)
        return cls(text, response=_Response(status=status))

    def test_success(self):
        records = self._capture_logs()
        guests = [_guest(100), _guest(101, status='stopped'), _guest(102, template=1)]
        self._scrape(_answers(guests=guests))
        minted, _ = self._mint()
        self.assertEqual(PASSWORD, minted.ticket)

        logged = self._assert_clean(records)
        # The capture saw the driver's logging, so its silence means
        # something.
        self.assertIn('Ignoring VM with incorrect status', logged)

    def test_discovery_failures(self):
        records = self._capture_logs()
        for path, failure in (
                ('/nodes/pve1/qemu/100/config', self._leaky(requests.exceptions.HTTPError, status=500)),
                ('/nodes/pve1/qemu/100/config', self._leaky(requests.exceptions.ConnectionError)),
                ('/nodes/pve1/certificates/info', self._leaky(requests.exceptions.HTTPError, status=595))):
            answers = _answers()
            answers[('GET', API + path)] = failure
            with self.assertRaises(type(failure)):
                self._scrape(answers)

        logged = self._assert_clean(records)
        self.assertIn('HTTPError', logged)
        self.assertIn('ConnectionError', logged)
        self.assertIn('595', logged)

    def test_mint_failures(self):
        records = self._capture_logs()
        for path, failure in (
                (('GET', '/cluster/resources'), self._leaky(requests.exceptions.HTTPError, status=401)),
                (('GET', '/nodes/pve1/qemu/100/config'), self._leaky(requests.exceptions.Timeout)),
                (('POST', '/nodes/pve1/qemu/100/spiceproxy'),
                 self._leaky(requests.exceptions.HTTPError, status=500))):
            answers = _answers()
            answers[(path[0], API + path[1])] = failure
            with self.assertRaises(type(failure)):
                self._mint(answers=answers)

        for answers in (_answers(configs={100: _config(smbios1='uuid=%s' % OTHER_SMBIOS)}),
                        _answers(guests=[_guest(status='stopped')]),
                        _answers(spiceproxy=_spiceproxy(**{'tls-port': None}))):
            with self.assertRaises(base.ConsoleTicketUnavailable):
                self._mint(answers=answers)

        logged = self._assert_clean(records)
        for expected in ('HTTPError', '401', 'Timeout', '500', 'incomplete ticket',
                         'not the machine'):
            self.assertIn(expected, logged)
        self.assertNotIn(SMBIOS, logged)
        self.assertNotIn(OTHER_SMBIOS, logged)
