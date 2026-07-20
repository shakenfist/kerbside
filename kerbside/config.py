import configparser
import os
import sys

from pydantic import Field
from pydantic_settings import BaseSettings


ENV_PREFIX = 'KERBSIDE_'
INI_PATH = '/etc/kerbside/kerbside.ini'
INI_SECTION = 'kerbside'


def load_ini_settings():
    if os.path.exists(INI_PATH):
        print(f'PID {os.getpid()} reading configuration INI file at {INI_PATH}')
        c = configparser.ConfigParser()
        try:
            c.read(INI_PATH)
            processed = 0
            skipped = 0

            for k in c[INI_SECTION]:
                env_var_name = f'{ENV_PREFIX}{k.upper()}'
                if env_var_name in os.environ:
                    print(f'Not overriding environment variable: {env_var_name}')
                    skipped += 1
                else:
                    print(f'Setting {env_var_name}...')
                    os.environ[env_var_name] = str(c[INI_SECTION][k])
                    processed += 1

            print(f'PID {os.getpid()} INI file processing complete: set '
                  f'{processed}, skipped {skipped}')

        except configparser.Error as e:
            print(f'PID {os.getpid()} error reading INI file: {e}')
            sys.exit()


class Config(BaseSettings):
    # JWT configuration
    AUTH_SECRET_SEED: str = Field(
        '~~unconfigured~~', description='A random string to seed auth secrets with'
    )
    API_TOKEN_DURATION: int = Field(
        60,
        description='Validitity duration for API access tokens in minutes')

    # OpenStack authentication details, used for validating API and web interface
    # clients, but separate from the auth details used for the target OpenStack
    # deployments. That is, your auth keystone can be different from the ones
    # used by target clouds if you are that way inclined.
    KEYSTONE_AUTH_URL: str = Field(
        '~~unconfigured~~',
        description='The URL to the keystone service we should auth against'
    )
    KEYSTONE_AUTH_VERIFY: bool | str = Field(
        True,
        description=(
            'Whether or not to verify TLS sessions to Keystone, as per the '
            'behaviour of keystoneauth1.session: False to not verify; True to '
            'verify using the system configured CA bundle; or a path to a CA '
            'certificate or CA bundle to use a specific certificate.'
        )
    )
    KEYSTONE_SERVICE_AUTH_USER: str = Field(
        '~~unconfigured~~',
        description='The user to authenticate this service as'
    )
    KEYSTONE_SERVICE_AUTH_PASSWORD: str = Field(
        '~~unconfigured~~',
        description='The password to use while authenticating the service user'
    )
    KEYSTONE_SERVICE_AUTH_USER_DOMAIN_ID: str = Field(
        'default',
        description='The keystone user domain the service auth user resides in'
    )
    KEYSTONE_SERVICE_AUTH_PROJECT: str = Field(
        'admin',
        description='The keystone project the service auth user resides in'
    )
    KEYSTONE_SERVICE_AUTH_PROJECT_DOMAIN_ID: str = Field(
        'default',
        description='The keystone project domain if the service auth user resides in'
    )
    KEYSTONE_ACCESS_GROUP: str = Field(
        'kerbside',
        description='The keystone group users must exist in to access the proxy'
    )

    PUBLIC_FQDN: str = Field(
        'kerbside.home.stillhq.com',
        description=('The public fully qualified domain name for kerbside. This '
                     'could be a load balancer with backend affinity.'))
    SF_CONSOLE_TOKEN_AUDIENCE: str = Field(
        '',
        description=(
            'The expected "aud" claim for Shaken Fist VDI console tokens '
            'exchanged at /sf-console.vv. Empty means derive it as '
            'https://<PUBLIC_FQDN>. This value must equal Shaken Fist\'s '
            'KERBSIDE_URL exactly -- it is both the token audience and the '
            'base of the exchange URL, so set it explicitly when the public '
            'URL differs in scheme, port, or path.'))
    PUBLIC_SECURE_PORT: int = Field(
        5900,
        description=(
            'Port secure connections should connect to on the PUBLIC_FQDN. This '
            'can be different from VDI_SECURE_PORT if there is a load balancing '
            'layer in front of Kerbside'
        )
    )
    PUBLIC_INSECURE_PORT: int = Field(
        5901,
        description=(
            'Port insecure connections should connect to on the PUBLIC_FQDN. This '
            'can be different from VDI_SECURE_PORT if there is a load balancing '
            'layer in front of Kerbside'
        )
    )

    NODE_NAME: str = Field(
        'kerbside',
        description='The private unique name for this machine.')
    VDI_ADDRESS: str = Field(
        '0.0.0.0',
        description='The IPv4 address to bind the SPICE proxy to.')
    VDI_SECURE_PORT: int = Field(
        5900,
        description=(
            'Port to bind to for secure SPICE connections on the node '
            'running Kerbside'
        )
    )
    VDI_INSECURE_PORT: int = Field(
        5901,
        description=(
            'Port to bind to for insecure SPICE connections on the node '
            'running Kerbside'
        )
    )

    # Logging
    LOG_OUTPUT_PATH: str = Field(
        '',
        description=('The path to write logs to. If blank we use syslog, use '
                     'the special value of "stdout" for console logs.'))
    LOG_OUTPUT_JSON: bool = Field(
        False,
        description='Set to true to output JSON log messages, one per line.')
    LOG_VERBOSE: bool = Field(
        False,
        description='Should we output debug logs?')

    # Firewall policy delivered to the (Rust) SPICE proxy in the
    # AuthorizeConnection reply. Python owns the policy; the proxy enforces it.
    # Only the knobs with a real config surface are delivered; size caps and
    # the rate ceiling keep the proxy's enforcing compiled defaults for now.
    FIREWALL_MODE: str = Field(
        'enforce',
        description=('Firewall enforcement mode delivered to the proxy: '
                     '"enforce" (default) applies blocking verdicts, "warn" '
                     'downgrades them to forward-and-log so an operator can '
                     'observe what enforcement would trip before enabling it. '
                     'Case-insensitive.'))
    FIREWALL_PERMITTED_CHANNELS: str = Field(
        '',
        description=('Comma-separated list of SPICE channel NAMES the proxy is '
                     'permitted to relay (main, display, inputs, cursor, '
                     'playback, record, tunnel, smartcard, usbredir, port, '
                     'webdav). Empty (the default) means permit all channels; '
                     'a channel not listed is denied before relay.'))

    # Metrics for monitoring
    PROMETHEUS_METRICS_PORT: int = Field(
        13003,
        description='Where to expose internal metrics. Do not allow '
                    'access from untrusted clients!')
    PROMETHEUS_METRICS_ADDRESS: str = Field(
        '127.0.0.1',
        description='Address the Rust proxy binds its /metrics server to. '
                    'Defaults to loopback because the endpoint is '
                    'unauthenticated and must not be exposed on the public '
                    'VDI interface; set a management address (or 0.0.0.0 '
                    'behind a firewall) to scrape from another host.')

    # Database and cloud inspection
    SQL_URL: str = Field(
        'mysql://kerbside:QwwMH-4w@kolla/kerbside',
        description='The SQLalchemy connection string for our MySQL database.')
    SOURCES_PATH: str = Field(
        './sources.yaml',
        description='A path to a sources.yaml file which lists VDI console sources.')

    # Proxy cryptography
    CACERT_PATH: str = Field(
        '/etc/pki/CA/ca-cert.pem',
        description='A path to the ca-cert.pem file for this proxy.')
    PROXY_HOST_SUBJECT: str = Field(
        'C=US,O=Shaken Fist,CN=Kerbside Proxy',
        description='The TLS host subject that matches the one set for VDI proxies.')
    PROXY_HOST_CERT_PATH: str = Field(
        '/etc/pki/CA/certs/proxy.pem',
        description='The TLS host certificate for the VDI proxy.')
    PROXY_HOST_CERT_KEY_PATH: str = Field(
        '/etc/pki/CA/certs/proxy-key.pem',
        description='The key for the TLS host certificate for the VDI proxy.')

    CONSOLE_TOKEN_DURATION: int = Field(
        1,
        description='How long in minutes a console token is valid for.')

    # KerbsideProxy gRPC control-plane service
    API_SOCKET_PATH: str = Field(
        '/run/kerbside/api.sock',
        description='Unix domain socket path for the KerbsideProxy gRPC service '
                    'the proxy consults for authorization and channel '
                    'bookkeeping. Keep this short: AF_UNIX socket paths are '
                    'limited to about 108 bytes (SUN_LEN), and an over-long '
                    'path fails to bind/connect. A path under /run is safe.')
    API_GRPC_WORKERS: int = Field(
        8,
        description='Thread pool size for the KerbsideProxy gRPC server.')

    class Config:
        env_prefix = ENV_PREFIX

    def __init__(self):
        load_ini_settings()
        super().__init__(self)


config = Config()
