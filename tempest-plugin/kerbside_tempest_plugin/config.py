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
    cfg.StrOpt(
        'control_socket_path',
        default=None,
        help='Path to the ryll headless control socket on the local host. '
             'When unset, the Sextant scenario test skips; this is the '
             'OpenStack-lane default.',
    ),
    cfg.StrOpt(
        'serial_log_path',
        default=None,
        help='Path to the qemu serial log file capturing the Sextant '
             "guest's serial output. The scenario test polls this file "
             'for the post-shutdown event drain.',
    ),
    cfg.StrOpt(
        'scenario_artifact_dir',
        default=None,
        help='Directory where the scenario test saves per-beat screenshots. '
             'When unset, screenshot capture is disabled without skipping '
             'the test.',
    ),
    cfg.IntOpt(
        'scenario_step_timeout',
        default=60,
        help='Per-beat deadline in seconds for each step of the Sextant '
             'scenario (waiting for digest events, the serial drain, etc.).',
    ),
]
