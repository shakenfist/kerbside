from pydantic import Field
from pydantic_settings import BaseSettings


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

    # API / admin server options
    API_ADDRESS: str = Field(
        '0.0.0.0',
        description='The IPv4 address to bind the REST API to')
    API_PORT: int = Field(
        13002,
        description='Port for the REST API')
    API_TIMEOUT: int = Field(
        30,
        description='How long gunicorn processes can use for a single request')
    API_COMMAND_LINE: str = Field(
        (
            '%(install_dir)s/gunicorn --workers %(workers)d --bind %(address)s:%(port)d '
            '--log-syslog --log-syslog-prefix kerbside --timeout %(timeout)s --name "%(name)s" '
            '--pid %(pid_file_dir)s/gunicorn.pid kerbside.api:app'
        ),
        description='The gunicorn command line to use')
    PID_FILE_LOCATION: str = Field(
        '/tmp/',
        description='Where the gunicorn PID file is located')
    PUBLIC_FQDN: str = Field(
        'kerbside.home.stillhq.com',
        description=('The public fully qualified domain name for kerbside. This '
                     'could be a load balancer with backend affinity.'))
    NODE_NAME: str = Field(
        'kerbside',
        description='The private unique name for this machine.')
    VDI_ADDRESS: str = Field(
        '0.0.0.0',
        description='The IPv4 address to bind the SPICE proxy to.')
    VDI_SECURE_PORT: int = Field(
        5900,
        description='Port for the secure SPICE connections')
    VDI_INSECURE_PORT: int = Field(
        5901,
        description='Port for the insecure SPICE connections')

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

    # Traffic inspection
    TRAFFIC_INSPECTION: bool = Field(
        False,
        description='Set to true to perform deep packet inspection of traffic.')
    TRAFFIC_INSPECTION_INTIMATE: bool = Field(
        False,
        description=('If TRAFFIC_INSPECTION is true, and TRAFFIC_INSPECTION_INTIMATE '
                     'is also set to true, then details such as keystrokes and '
                     'mouse movements will be logged.'))
    TRAFFIC_OUTPUT_PATH: str = Field(
        '',
        description=('The path to write traffic inspection logs to. This must be'
                     'be set if TRAFFIC_INSPECTION is True.'))

    # Metrics for monitoring
    PROMETHEUS_METRICS_PORT: int = Field(
        13003,
        description='Where to expose internal metrics. Do not allow '
                    'access from untrusted clients!')

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

    class Config:
        env_prefix = 'KERBSIDE_'


config = Config()
