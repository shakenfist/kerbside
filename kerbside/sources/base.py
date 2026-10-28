# A base class for VDI console source drivers
#
# kerbside.db imports MintedTicket from here, and the drivers import db, so
# this module, like the package's __init__, must not import db or a driver
# at module level.

from abc import ABC
from collections import namedtuple

# How to reach a console which is only reachable through an HTTP CONNECT
# proxy: dial proxy_uri, ask it for connect_host, and speak TLS on port
# through the tunnel. connect_host is a credential, like a ticket.
Tunnel = namedtuple('Tunnel', ['proxy_uri', 'connect_host', 'port'])


def tunnel_complete(tunnel):
    """Whether a Tunnel names a proxy, a connect host and a usable port."""
    return (isinstance(tunnel.proxy_uri, str) and bool(tunnel.proxy_uri) and
            isinstance(tunnel.connect_host, str) and bool(tunnel.connect_host) and
            isinstance(tunnel.port, int) and not isinstance(tunnel.port, bool) and
            0 < tunnel.port < 65536)


# A console ticket minted by a source, valid until expires (epoch seconds),
# and the Tunnel to reach the console through, or None to dial it directly.
MintedTicket = namedtuple('MintedTicket', ['ticket', 'expires', 'tunnel'], defaults=[None])


class ConsoleTicketUnavailable(Exception):
    """A source could not mint a console ticket. The message carries no secret."""


class BaseSource(ABC):
    # Set to True by sources which can mint a console ticket on demand.
    MINTS_TICKETS = False

    # Set to False by sources whose consoles can only be reached through kerbside.
    DIRECT_CONSOLES = True

    # Set by a source which finds while being built that it cannot work, for
    # example because its upstream is unreachable or misconfigured.
    errored = False

    def __init__(self, **kwargs):
        ...

    def __call__(self):
        ...

    def close(self):
        ...

    def mint_console_ticket(self, uuid, lifetime):
        """Mint a ticket for connecting to a console.

        Returns a MintedTicket whose ticket is valid until expires (epoch
        seconds). lifetime is the requested validity in seconds. Sources
        honour it where their API allows, and otherwise report the shorter
        expiry the upstream actually granted. A source whose console is
        reached through a CONNECT proxy also returns the Tunnel it minted
        with the ticket. The two are stored and reused together, so expires
        must cover both: when they expire separately, it is the earlier of
        the two. Only sources with MINTS_TICKETS set implement this. Failure
        raises, never returns None: the source raises ConsoleTicketUnavailable
        for what it can diagnose itself, and lets its API client's exceptions
        through otherwise.
        """
        raise NotImplementedError()
