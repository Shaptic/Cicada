""" Establishes the user-facing API.
"""
import struct

from ..         import chordlib
from ..         import packetlib

from ..chordlib  import localnode
from ..packetlib import message as pktmsg
from ..packetlib import chord   as chordpkt
from ..packetlib import utils   as pktutils
from ..packetlib import cicada  as cicadapkt
# import packetlib.kamelia as kamelpkt


class SwarmException(Exception):
    pass


def bind_first(fn):
    def wrapper(self, *args, **kwargs):
        if self.peer is None:
            raise SwarmException("You must call bind() before connect().")
        return fn(self, *args, **kwargs)
    return wrapper


class SwarmPeer(object):
    """ Establishes a peer in a Cicada swarm.

    Mimics the `socket.socket` interface as closely as possible. Unlike that
    interface, though, `bind` is _required_, since every peer in the swarm acts
    like a server for all others.
    """
    NOOP_RESPONSE = lambda *args: None

    def __init__(self, hooks={}):
        self.peer = None    # the peer in the network, established on `bind()`
        self._read_queue = pktutils.ConditionQueue()
        self.hooks = {
            "send": hooks.get("send", self.NOOP_RESPONSE),
            "recv": hooks.get("recv", self.NOOP_RESPONSE),
        }

    def bind(self, hostname, port, external_ip, external_port):
        data = "%s:%d" % (external_ip, external_port)
        self.peer = localnode.LocalNode(data, (hostname, port),
                                        on_send=self.hooks["send"],
                                        on_data=self._on_data)

    @bind_first
    def connect(self, network_host, network_port, timeout=10):
        self.peer.join_ring((network_host, network_port), timeout)

    @bind_first
    def disconnect(self):
        self.peer.leave_ring()

    @bind_first
    def broadcast(self, data, visited=[]):
        """ Sends a data packet to every peer in the network.
        """
        peers = set(self.peer.routing_table.unique_iter(0))

        pkt = cicadapkt.BroadcastMessage(data, map(lambda x: x.hash, peers),
                                         visited=visited)
        for peer in filter(lambda p: p.hash not in visited, peers):
            self.peer.lookup(peer.hash, self.NOOP_RESPONSE, None,
                             data=pkt.pack())

    @bind_first
    def send(self, target, data, duplicates=0):
        """ Sends a data packet into the Cicada network.

        We wrap the data into a special routing packet and send it through the
        standard underlying DHT protocol.

        :target         a 2-tuple (hostname, port), a `chordlib.routing.Hash`,
                        or another `SwarmPeer` instance
        :data           the raw data to pack and send
        :duplicates[=0] the amount of extra peers to route the message through
        """
        if isinstance(target, tuple) and len(target) == 2:
            dest = "%s:%d" % target
            dest = chordlib.routing.Hash(value=dest)

        elif isinstance(target, chordlib.routing.Hash):
            dest = target

        elif isinstance(target, SwarmPeer) and target.peer:
            dest = target.peer.hash

        else:
            raise TypeError("expected (host, port), Hash, or SwarmPeer, "
                            " got: %s" % type(target))

        pkt = cicadapkt.DataMessage(data)
        peer = self.peer.lookup(dest, self.NOOP_RESPONSE, None, data=pkt.pack())
        exclusion = set((peer, ))
        for i in xrange(duplicates):
            try:
                peer = self.peer.lookup(dest, self.NOOP_RESPONSE, None,
                                        data=pkt.pack(), exclude=exclusion)
                exclusion.add(peer)
            except: break

    @bind_first
    def recv(self):
        """ Blocks until a data message is received from the Cicada network.

        This blocks the current thread, waiting for a signal to be triggered by
        the internal message processing thread. If there are already pending
        messages, this will return immediately.

        :returns    a 3-tuple of the source peer that the message came from,
                    the (unpacked) data message we received, and whether or not
                    there are more messages waiting to be popped
        """
        with self._read_queue:
            self._read_queue.wait()
            source, data = self._read_queue.pop()    # unpacked

            # Process Cicada messages first.
            # TODO: put this in a more sensible place.
            msg_type, = struct.unpack("!H", data[:2])
            if msg_type == cicadapkt.BroadcastMessage.SECONDARY_TYPE:
                pkt = cicadapkt.BroadcastMessage.unpack(data)
                pkt.visited.append(source.hash)     # sender has been visited
                self.broadcast(pkt.data, pkt.visited)
                data = pkt.data

            elif msg_type == cicadapkt.DataMessage.SECONDARY_TYPE:
                pkt = cicadapkt.DataMessage.unpack(data)
                data = pkt.data

            else:
                import pdb; pdb.set_trace()
                raise ValueError("Received unknown data packet.")

            return source, data, self._read_queue.ready

    @bind_first
    def get_route(self, value, on_result):
        """ Finds the resulting peer for a value asynchronously.

        See `localnode.LocalNode.lookup` for further documentation.
        """
        return self.peer.lookup(value, on_result, None)

    @bind_first
    def close(self):
        """ Closes all background tasks and shuts down the peer.
        """
        self.peer.stable.stop_running()
        self.peer.router.stop_running()
        self.peer.processor.stop_running()
        self.peer.listen_thread.stop_running()

        self.peer.stable.join(5)
        self.peer.router.join(5)
        self.peer.processor.join(5)
        self.peer.listen_thread.join(5)
        self.peer = None

    @property
    @bind_first
    def listener(self):
        return self.peer.chord_addr

    @property
    @bind_first
    def hash(self):
        return self.peer.hash

    @property
    @bind_first
    def peers(self):
        return self.peer.peers

    @property
    def peek(self):
        self._read_queue.ready

    def _on_data(self, source_peer, data):
        self._read_queue.push((source_peer, data))

    def __repr__(self):
        return repr(self.peer)


if __name__ == '__main__':
    a, b = SwarmPeer(), SwarmPeer()

    def src_on_recv(source, packet, more):
        print "Received '%s' from %s:%d." % (
            repr(packet), source.listener[0], source.listener[1])

    def dst_on_recv(source, packet, more):
        src_on_recv(source, packet, more)
        print "Echoing."
        b.send(source, packet[::-1])

    a.bind("localhost", 0xC1CADA & 0xFFFF)
    b.bind("localhost", 0xC1CADA & 0xFFFE)

    a.add_receive_hook(src_on_recv)
    b.add_receive_hook(dst_on_recv)

    b.connect(a.listener)
    a.send(b, "ECHO ME")
