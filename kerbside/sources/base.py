# A base class for VDI console source drivers

from abc import ABC


class BaseSource(ABC):
    def __init__(self, **kwargs):
        ...

    def __call__(self):
        ...

    def close(self):
        ...
