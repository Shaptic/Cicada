#! /usr/bin/env python2
import struct
import netinfo

from . import portmapper


class NatPMP(portmapper.PortMapper):
    """ Manages and caches port mappings for listeners.
    """
    ERRORS = {
        0: "Success",
        1: "Unsupported Version",
        2: "Not Authorized/Refused",
        3: "Network Failure",
        4: "Out of resources",
        5: "Unsupported opcode",
    }

    def __init__(self, local_address=None):
        super(NatPMP, self).__init__(local_address)
        self.name = "NatPMP"
        self._socket = None

    def create(self, timeout=30):
        """ Pings the gateway to retrieve the external IP.
        """
        null_addr, gateway = ipaddress.IPv4Address(0), None

        # Find the gateway address.
        for route in netinfo.get_routes():
            gw_addr = ipaddress.IPv4Address(route["gateway"].encode("unicode"))
            if gw_addr != null_addr:
                gateway = gw_addr  # choose first valid address
                break
        else:
            print "Failed to find a valid gateway address."
            return False

        print "Chose gateway:", gateway
        self._gateway = gateway

        # https://tools.ietf.org/html/rfc6886#section-3.2
        request = struct.pack("!BB", 0, 0)
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket.sendto(request, (gateway, 5350))

        self._socket.bind(("224.0.0.1", 5350))

        rd, _, _ = select.select([self._socket], [], [], timeout)
        if not rd:
            print "Timed out waiting for a NatPMP response."
            return False

        response, address = self._socket.recvfrom(12)
        version, opcode, result, seconds, ip = struct.unpack("!BBBII")

        self.externalipaddress = str(ipaddress.IPv4Address(ip))
        super(UPnP, self).create()

    def add_port_mapping(self, local_port, external_port, protocol="tcp",
                         lifetime=3600, timeout=10):
        """ Maps an external port to the local port.
        """
        rv = super(UPnP, self).add_port_mapping(local_port, external_port,
                                                protocol)
        if not rv: return False

        # https://tools.ietf.org/html/rfc6886#section-3.3
        opcode = 2 if protocol.upper() == "TCP" else 1
        data = struct.pack("!BBHHHI", 0, opcode, local_port, external_port,
                           lifetime)
        self._socket.sendto(data, (gateway, 5350))

        while True:
            rd, _, _ = select.select([self._socket], [], [], timeout)
            if not rd:
                print "Timed out waiting for NatPMP response."
                return False

            response, address = self._socket.recvfrom(12)
            if ipaddress.IPv4Address(address[0]) != self._gateway:
                continue

            v, op, result, s, local, external, lifetime = struct.unpack(
                "!BBHIHHI", response)

            if op - 128 != opcode:
                print "The response didn't match the request!"
                return False

            if result != 0:
                print "The result code indicated failure:", self.ERRORS[result]
                return False

            if external_port != external:
                print "The mapped external port doesn't match the request!"
                return False

            print "Mapping lifetime: %ds" % lifetime
            return True

    def delete_port_mapping(self, local_port, protocol="tcp"):
        rv = self.add_port_mapping(local_port, 0, protocol=protocol, lifetime=0)
        self._remove_from_cache(local_port)
        return rv
