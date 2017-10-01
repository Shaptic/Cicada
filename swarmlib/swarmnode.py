""" Establishes the user-facing API.
"""
import chordlib
import chordlib.localnode as localnode

import packetlib
import packetlib.message as pktmsg
import packetlib.chord   as chordpkt
import packetlib.utils   as pktutils
import packetlib.cicada  as cicadapkt
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

    def __init__(self, hooks):
        self.peer = None    # the peer in the network, established on `bind()`
        self._read_queue = pktutils.ConditionQueue()
        self.hooks = {
            "send": hooks.get("send", self.NOOP_RESPONSE),
            "recv": hooks.get("recv", self.NOOP_RESPONSE),
        }

    def bind(self, hostname, port):
        data = "%s:%d" % (hostname, port)
        self.peer = localnode.LocalNode(data, (hostname, port),
                                        on_send=self.hooks["send"],
                                        on_data=self._on_data)

    @bind_first
    def connect(self, network_host, network_port, timeout=10):
        self.peer.join_ring((network_host, network_port), timeout)

    @bind_first
    def broadcast(self, data):
        """ Sends a data packet to every peer in the network.
        """
        peers = set(self.peer.routing_table.unique_iter(0))

        import pdb; pdb.set_trace()
        pkt = cicadapkt.BroadcastMessage(data, map(lambda x: x.hash, peers))
        for peer in peers:
            print "Sending %s to %s:%d." % (repr(pkt), peer.chord_addr[0],
                                            peer.chord_addr[1])
            self.peer.lookup(peer.hash, self.NOOP_RESPONSE, None,
                             data=pkt.pack())

    @bind_first
    def send(self, target, data):
        """ Sends a data packet into the Cicada network.

        We wrap the data into a special routing packet and send it through the
        standard underlying DHT protocol.

        :target     either a 2-tuple (hostname, port) or another `SwarmPeer`
        :data       the raw data to pack and send
        """
        if isinstance(target, tuple) and len(target) == 2:
            dest = "%s:%d" % target
            dest = chordlib.routing.Hash(value=dest)

        elif isinstance(target, SwarmPeer) and target.peer:
            dest = target.peer.hash

        else:
            raise TypeError("expected (host, port) or SwarmPeer, got: %s" %
                            type(target))

        pkt = cicadapkt.DataMessage.make_packet(data)
        self.peer.lookup(dest, self.NOOP_RESPONSE, None, data=pkt.pack())

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
            pair = self._read_queue.pop()    # unpacked
            return pair[0], pair[1], self._read_queue.ready

    @bind_first
    def get_route(self, value, on_result):
        """ Finds the resulting peer for a value asynchronously.

        See `localnode.LocalNode.lookup` for further documentation.
        """
        return self.peer.lookup(value, on_result, None)

    @property
    @bind_first
    def listener(self):
        return self.peer.chord_addr

    @property
    @bind_first
    def hash(self):
        return self.peer.hash

    def _on_data(self, data):
        self._read_queue.push(data)

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
