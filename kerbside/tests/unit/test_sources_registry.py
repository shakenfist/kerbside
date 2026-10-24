import testtools

from kerbside import sources
from kerbside.sources import base
from kerbside.sources import ovirt
from kerbside.sources import shakenfist
from kerbside.sources import static


class DriverClassTestCase(testtools.TestCase):
    def test_shakenfist(self):
        self.assertIs(shakenfist.ShakenFistSource, sources.driver_class('shakenfist'))

    def test_ovirt(self):
        self.assertIs(ovirt.oVirtSource, sources.driver_class('ovirt'))

    def test_static(self):
        self.assertIs(static.StaticSource, sources.driver_class('static'))

    def test_openstack_has_no_driver(self):
        self.assertRaises(KeyError, sources.driver_class, 'openstack')

    def test_unknown_type(self):
        self.assertRaises(KeyError, sources.driver_class, 'nonsense')


class BaseSourceHooksTestCase(testtools.TestCase):
    def test_does_not_mint_by_default(self):
        self.assertFalse(base.BaseSource.MINTS_TICKETS)

    def test_mint_console_ticket_not_implemented(self):
        self.assertRaises(
            NotImplementedError,
            base.BaseSource().mint_console_ticket, 'uuid', 60)

    def test_minted_ticket_fields(self):
        minted = base.MintedTicket(ticket='t', expires=12.5)
        self.assertEqual(('t', 12.5), (minted.ticket, minted.expires))
