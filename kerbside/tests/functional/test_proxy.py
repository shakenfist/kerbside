import testtools


from kerbside import spiceprotocol


class ConnectionInitiationTests(testtools.TestCase):
    def setUp(self):
        super(ConnectionInitiationTests, self).setUp()

        # Cache our CA cert. This should be a better place than this.
        with open('/etc/pki/CA/ca-cert.pem') as f:
            self.ca_cert = f.read()

    def test_bad_magic(self):
        sc = spiceprotocol.SpiceClient()
        sc.from_static_configuration(
            'kerbside.home.stillhq.com', 5900, 5901, '', self.ca_cert, None)
        spiceprotocol.packets.linkmessages._SpiceLinkMessPacket.magic = b'MIKL'
        self.assertRaises(
            spiceprotocol.packets.linkmessages.HandshakeFailed, sc.connect)

    def test_bad_major(self):
        sc = spiceprotocol.SpiceClient()
        sc.from_static_configuration(
            'kerbside.home.stillhq.com', 5900, 5901, '', self.ca_cert, None)
        spiceprotocol.packets.linkmessages._SpiceLinkMessPacket.major = 1
        self.assertRaises(
            spiceprotocol.packets.linkmessages.HandshakeFailed, sc.connect)

    def test_bad_minor(self):
        sc = spiceprotocol.SpiceClient()
        sc.from_static_configuration(
            'kerbside.home.stillhq.com', 5900, 5901, '', self.ca_cert, None)
        spiceprotocol.packets.linkmessages._SpiceLinkMessPacket.minor = 1
        self.assertRaises(
            spiceprotocol.packets.linkmessages.HandshakeFailed, sc.connect)

    def test_no_tls_port(self):
        sc = spiceprotocol.SpiceClient()
        sc.from_static_configuration(
            'kerbside.home.stillhq.com', 5900, None, '', self.ca_cert, None)
        self.assertRaises(spiceprotocol.NoTLSPort, sc.connect)

    def test_invalid_password(self):
        sc = spiceprotocol.SpiceClient()
        sc.from_static_configuration(
            'kerbside.home.stillhq.com', 5900, 5901, '', self.ca_cert, None)
        self.assertRaises(
            spiceprotocol.packets.authentication.AuthenticationDisconnect,
            sc.connect)
        self.assertTrue(sc.secure)
