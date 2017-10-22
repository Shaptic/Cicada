#! /usr/bin/env python2
from . import upnp
from . import natpmp

PortMapper = None

class PortMapping(object):
    def __init__(self, port, protocol="tcp"):
        self.mapper = None
        for portmapping_type in (upnp.UPnP, natpmp.NatPMP):
            session = portmapping_type()
            try:
                session.create()
                break

            except Exception, e:
                print "An error occurred:", str(e)
        else:
            return

        self.mapper = session
        self.port, self.protocol = port, protocol.upper()

        global PortMapper
        PortMapper = session

    def __enter__(self):
        if not self.mapper.add_port_mapping(self.port, self.port,
                                            self.protocol):
            print "Failed to map %d." % (self.port)
            self.port = None
            return False

        self.eport = self.mapper.mappings[self.port][0]
        print "Succeeded in mapping %d:%d." % (self.port, self.eport)
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if not self.port: return
        print "Removed mapping %d:%d." % (self.port, self.eport)
        self.mapper.delete_port_mapping(self.port, self.protocol)

