from oslo_config import cfg


kerbside_group = cfg.OptGroup(
    name='kerbside',
    title='Kerbside SPICE VDI proxy options',
)

KerbsideGroup = [
    cfg.StrOpt(
        'ca_cert_path',
        default='/etc/kolla/certificates/ca/root.crt',
        help='Path to the CA bundle used to verify the HTTPS endpoint '
             'Nova returns when SPICE console access is configured to '
             'flow through Kerbside. The SPICE proxy connection itself '
             'is verified using the CA embedded in the .vv file Kerbside '
             'serves at that endpoint.',
    ),
    cfg.IntOpt(
        'handshake_timeout',
        default=30,
        help='Socket timeout, in seconds, for the SPICE link handshake '
             'performed against the Kerbside proxy.',
    ),
]
