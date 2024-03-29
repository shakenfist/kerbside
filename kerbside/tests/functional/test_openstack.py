from keystoneauth1.identity import v3
from keystoneauth1 import session
from openstack import connection
import requests
from shakenfist_utilities import random as sf_random
import testtools
import time
import yaml


from .. import spiceprotocol


class OpenStackTestCase(testtools.TestCase):
    def setUp(self):
        super(OpenStackTestCase, self).setUp()

        # Load config details from sources.yaml
        with open('sources.yaml') as f:
            sources = yaml.safe_load(f)

        kolla_source = None
        for source in sources:
            if source['source'] == 'kolla':
                kolla_source = source
        if not kolla_source:
            self.fail('Failed to find kolla source')

        # Authenticate
        auth = v3.Password(
            auth_url=kolla_source['url'],
            username=kolla_source['username'],
            password=kolla_source['password'],
            project_name=kolla_source['project_name'],
            user_domain_id=kolla_source['user_domain_id'],
            project_domain_id=kolla_source['project_domain_id'])
        self.conn = connection.Connection(session=session.Session(auth=auth))

        # Find the right image
        self.test_image = None
        for image in self.conn.compute.images():
            if image.get('metadata', {}).get('hw_video_ram'):
                self.test_image = image
        if not self.test_image:
            self.fail('No test image found')

        # Start a target instance
        flavor = self.conn.compute.find_flavor('vdi')
        network = self.conn.network.find_network('public1')

        self.instance_name = 'kerbside-test-%s' % sf_random.random_id()
        self.instance = self.conn.compute.create_server(
            name=self.instance_name,
            image_id=self.test_image.id,
            flavor_id=flavor.id,
            networks=[{'uuid': network.id}],
        )

        self.conn.compute.wait_for_server(self.instance)

    def tearDown(self):
        super(OpenStackTestCase, self).tearDown()

        if self.instance:
            self.conn.compute.delete_server(self.instance)


class OpenStackDirectTests(OpenStackTestCase):
    def test_connect(self):
        # Lookup connection details
        console_data = self.conn.compute.create_console(
            self.instance, console_type='spice-direct')
        if 'port' not in console_data or not console_data['port']:
            self.fail('Console lookup failed')

        # Construct a SPICE client from that config
        sc = spiceprotocol.SpiceClient()
        sc.from_static_configuration(
            console_data['host'], console_data['port'], console_data.get('tls_port'),
            '', None, None)
        sc.connect()


class OpenStackProxyVirtViewerTests(OpenStackTestCase):
    def test_connect(self):
        # Fetch the virt viewer configuration for the instance from the proxy
        url = ('http://kerbside.home.stillhq.com:13002/console/proxy/'
               'kolla/%s/console.vv' % self.instance.id)

        # It can take up to a minute for the console to appear with the proxy
        start_time = time.time()
        while time.time() - start_time < 90:
            r = requests.get(url)
            if r.status_code == 200:
                vv = r.text
                break
            time.sleep(30)

        if time.time() - start_time > 89:
            self.fail('Console for %s never appeared in the proxy'
                      % self.instance.id)

        # Construct a SPICE client from that config
        sc = spiceprotocol.SpiceClient()
        sc.from_vv_file(vvconfig=vv)
        sc.connect()
