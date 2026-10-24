# A base class for VDI console source drivers

from abc import ABC
from collections import namedtuple

# A console ticket minted by a source, valid until expires (epoch seconds).
MintedTicket = namedtuple('MintedTicket', ['ticket', 'expires'])


class BaseSource(ABC):
    # Set to True by sources which can mint a console ticket on demand.
    MINTS_TICKETS = False

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
        expiry the upstream actually granted. Only sources with MINTS_TICKETS
        set implement this.
        """
        raise NotImplementedError()
