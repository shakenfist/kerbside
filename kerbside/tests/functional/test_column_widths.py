"""The longest values a source driver produces are stored unchanged.

SQLite ignores a VARCHAR's length, so the unit tests cannot show that a
value fits its column. MariaDB in strict mode refuses one that does not, and
without strict mode cuts it short, so these tests store each value and read
it back against a real MariaDB or MySQL server named by
KERBSIDE_TEST_SQL_URL, and are skipped when it is unset.

The database the URL names is dropped and recreated, and dropped again at
the end, so its name must end in 'test'; see sql_database.

These tests use the standard library's unittest rather than testtools so
that they run in an environment holding only kerbside's runtime
dependencies:

    KERBSIDE_TEST_SQL_URL=mysql://user:pass@127.0.0.1/kerbside_locktest \\
        python -m unittest -v kerbside.tests.functional.test_column_widths
"""

import time
import unittest
from unittest import mock

from sqlalchemy import create_engine

from kerbside import db
from kerbside.sources import proxmox
from kerbside.tests.functional import sql_database


SOURCE = 'widthtest-source'
URL = 'https://pve1.example:8006'
TOKEN_ID = 'kerbside@pve!broker'

# The largest vmid PVE accepts (pve-common's pve-vmid format allows nine
# digits), which gives the longest console uuid the driver can produce.
VMID = 999999999
SMBIOS = '3f0c9a52-1b7e-4d8a-9c2f-5e6d7a8b9c0d'

# consoletokens.session_id is a String(12).
SESSION_ID = 'width-sessn1'


@unittest.skipUnless(sql_database.TEST_SQL_URL,
                     'KERBSIDE_TEST_SQL_URL is not set')
class ColumnWidthTestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.url = sql_database.migrated_database()
        cls.engine = create_engine(cls.url, hide_parameters=True)
        cls.engine_patch = mock.patch.object(db, 'ENGINE', cls.engine)
        cls.engine_patch.start()

    @classmethod
    def tearDownClass(cls):
        cls.engine_patch.stop()
        cls.engine.dispose()
        sql_database.drop_database(cls.url)
        super().tearDownClass()

    def test_proxmox_console_uuid_round_trips(self):
        uuid = proxmox.console_uuid(VMID, SMBIOS)
        # Ten characters past the 36 of a bare UUID.
        self.assertEqual(46, len(uuid))
        now = int(time.time())

        db.add_source(SOURCE, 'proxmox', URL, TOKEN_ID, 'not-a-secret')
        db.add_console(
            source=SOURCE, uuid=uuid, hypervisor='pve1', hypervisor_ip='',
            insecure_port=None, secure_port=None, name='vm',
            host_subject='CN=pve1.example', ticket=None)
        db.add_token('widthtest-token', SESSION_ID, SOURCE, uuid,
                     now, now + 3600)
        db.add_audit_event(SOURCE, uuid, SESSION_ID, 'main', 'node1',
                           'connection-ref', 'width test event')

        console = db.get_console(SOURCE, uuid)
        self.assertIsNotNone(console)
        self.assertEqual(uuid, console['uuid'])
        self.assertEqual((VMID, SMBIOS),
                         proxmox.parse_console_uuid(console['uuid']))

        token = db.get_token_by_session_id(SESSION_ID)
        self.assertEqual(uuid, token['uuid'])
        self.assertEqual(
            ['widthtest-token'],
            [t['token'] for t in db.get_tokens_by_console(SOURCE, uuid)])

        events = db.get_audit_events(SOURCE, uuid)
        self.assertEqual([(uuid, 'width test event')],
                         [(e['uuid'], e['message']) for e in events])

    def test_long_source_username_round_trips(self):
        # A PVE API token ID, user@realm!tokenid, with long names in it.
        username = ('kerbside-console-broker@ldap-corporate-directory!'
                    'spice-console-brokering-token-01')
        username += 'x' * (100 - len(username))
        self.assertEqual(100, len(username))

        db.add_source('widthtest-long-username', 'proxmox', URL, username,
                      'not-a-secret')

        source = db.get_source('widthtest-long-username')
        self.assertEqual(username, source['username'])


if __name__ == '__main__':
    unittest.main()
