#! /usr/bin/env python2
import socket


class PortMapper(object):
    """ Manages and caches port mappings for listeners.
    """
    def __init__(self, local_address=None):
        # Learn local interface address, if not provided.
        if not local_address:
            local_address = PortMapper.get_local_address()

        self.local_address = local_address
        self.mappings = {}  # { ushort: ushort }, port mappings
        self.external_ip = None

    def create(self):
        """ Performs basic discovery of the network and various properties.
        """
        assert self.external_ip != None, "External IP must be set by parent!"

    def add_port_mapping(self, local_port, external_port, protocol="tcp"):
        """ Adds a new port mapping to the gateway.
        """
        if local_port in self.mappings:
            print "The mapping for %d already exists: %d[%s]" % (
                local_port, self.mappings[local_port][0],
                self.mappings[local_port][1])
            return False

        self.mappings[local_port] = (external_port, protocol.upper())
        return True

    def cleanup(self):
        """ Deletes all port mappings and clears the cache.
        """
        self.mappings = {}

    def _remove_from_cache(self, local_port):
        """ Removes a port mapping from the internal cache.
        """
        self.mappings.pop(local_port, None)

    @staticmethod
    def get_local_address():
        """ Retrieves the local interface address.
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        addr = s.getsockname()[0]
        s.close()
        return addr
