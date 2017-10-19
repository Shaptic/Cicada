#! /usr/bin/env python2
from . import portmapper

class NatPMP(portmapper.PortMapper):
    """ Manages and caches port mappings for listeners.
    """
    def __init__(self, local_address=None):
        pass
