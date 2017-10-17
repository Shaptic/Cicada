import os
import random
import string
import unittest

import sys
sys.path.append(".")


from cicada.packetlib import debug
from cicada.packetlib import chord
from cicada.packetlib import message
from cicada.chordlib  import routing
from cicada.chordlib  import chordnode


class TestHashing(unittest.TestCase):
    """ Tests that packing and unpacking hashes works.
    """
    HASH_COUNT = 1000

    def test_hashes(self):
        for i in xrange(self.HASH_COUNT):
            start = ''.join([
                random.choice(string.lowercase) for _ in xrange(
                    random.randint(10, 20)
                )
            ])

            # print "Hashing value: %s" % repr(start)
            h = routing.Hash(value=start)
            self.assertEqual(routing.Hash.pack_hash(str(h)), h.parts)


class TestMessagePacking(unittest.TestCase):
    """ Tests that the `.pack()` and `.unpack()` methods of each message works.
    """
    def test_messagecontainer(self):
        h = routing.Hash(value="sender")
        n = message.MessageContainer(message.MessageType.MSG_CH_NOTIFY, h,
                                     data="hey babes\x77hey", sequence=2884)
        # debug.dump_packet(n.pack(), n.full_format())
        self.assertEqual(n.pack(), self._repack(n.pack()))

    def test_inforequest(self):
        sender = routing.Hash(value="sender")
        pkt = chord.InfoRequest.make_packet(sender)
        # debug.dump_packet(pkt.pack(), pkt.full_format())
        self.assertEqual(pkt.pack(), self._repack(pkt.pack()))

    def test_inforesponse(self):
        sender = routing.Hash(value="sender")
        send_node = chordnode.ChordNode(sender, ("localhost", 0xB00B))

        req = chord.InfoRequest.make_packet(sender)
        req.pack()     # need to pack for checksum injection
        pkt = chord.InfoResponse.make_packet(sender, send_node, None, None,
                                             original=req)
        self.assertEqual(pkt.pack(), self._repack(pkt.pack()))

    def test_inforesponse_with_predecessor(self):
        sender = routing.Hash(value="sender")
        send_node = chordnode.ChordNode(sender, ("localhost", 0xB00B))

        req = chord.InfoRequest.make_packet(sender)
        req.pack()     # need to pack for checksum injection
        pkt = chord.InfoResponse.make_packet(sender, send_node, send_node,
                                             send_node, original=req)
        self.assertEqual(pkt.pack(), self._repack(pkt.pack()))

    def test_inforesponse_with_successor(self):
        sender = routing.Hash(value="sender")
        send_node = chordnode.ChordNode(sender, ("localhost", 0xB00B))

        req = chord.InfoRequest.make_packet(sender)
        req.pack()     # need to pack for checksum injection
        pkt = chord.InfoResponse.make_packet(sender, send_node, None, send_node,
                                             original=req)
        self.assertEqual(pkt.pack(), self._repack(pkt.pack()))

    def test_joinrequest(self):
        sender = routing.Hash(value="sender")
        pkt = chord.JoinRequest.make_packet(sender, ("127.0.0.1", 0xB00B))
        self.assertEqual(pkt.pack(), self._repack(pkt.pack()))

    def test_joinresponse(self):
        sender = routing.Hash(value="sender")
        send_node = chordnode.ChordNode(sender, ("localhost", 0xB00B))

        req = chord.JoinRequest.make_packet(sender, ("127.0.0.1", 0xB00B))
        req.pack()     # need to pack for checksum injection
        pkt = chord.JoinResponse.make_packet(sender, send_node, send_node, None,
                                             None, original=req)
        self.assertEqual(pkt.pack(), self._repack(pkt.pack()))

    def test_notifyrequest(self):
        self.test_inforequest()

    def test_notifyresponse_yes(self):
        self._notify_response(True)

    def test_notifyresponse_no(self):
        self._notify_response(False)

    def _notify_response(self, flag):
        sender = routing.Hash(value="sender")
        send_node = chordnode.ChordNode(sender, ("localhost", 0xB00B))

        req = chord.NotifyRequest.make_packet(sender, send_node, send_node,
                                              send_node); req.pack()

        pkt = chord.NotifyResponse.make_packet(sender, flag, original=req)
        self.assertEqual(pkt.pack(), self._repack(pkt.pack()))

    def test_lookuprequest(self):
        sender = routing.Hash(value="sender")
        lookup = routing.Hash(value="lookup")
        pkt = chord.LookupRequest.make_packet(sender, lookup)
        self.assertEqual(pkt.pack(), self._repack(pkt.pack()))

    def test_lookuprequest_with_data(self):
        sender = routing.Hash(value="sender")
        lookup = routing.Hash(value="lookup")

        for _ in xrange(100):
            data = os.urandom(random.randint(100, 10000))
            pkt = chord.LookupRequest.make_packet(sender, lookup, data)
            self.assertEqual(pkt.pack(), self._repack(pkt.pack()))

    def test_lookupresponse(self):
        sender = routing.Hash(value="sender")
        lookup = routing.Hash(value="lookup")

        req = chord.LookupRequest.make_packet(sender, lookup); req.pack()
        pkt = chord.LookupResponse.make_packet(sender, lookup, sender,
                                               ("127.0.0.1", 0xB00B), 5,
                                               original=req)
        self.assertEqual(pkt.pack(), self._repack(pkt.pack()))

    def _repack(self, bs):
        return message.MessageContainer.unpack(bs).pack()


if __name__ == '__main__':
    unittest.main()

# Stress testing process:
#
#  - Create a bunch of arbitrary nodes.
#  - Connect them all randomly.
#  - Ensure that after some time, each one's successor pointer is as close as it
#    can be, and likewise for the predecessor pointer.
#
"""
import sys
import time
import pprint
import random
import collections

from   ..chordlib import localnode
from   ..chordlib import routing

PEER_COUNT = int(sys.argv[1]) if len(sys.argv) > 1 else 25
start_port = random.randint(10000, (2 ** 16) - PEER_COUNT - 1)
peers = []
print "Creating %d peers..." % PEER_COUNT
for i in xrange(PEER_COUNT):
    address = ("localhost", start_port + i)
    peer = localnode.LocalNode("%s:%d" % address, address)

    def pred(n, o, p):
        print "  Peer", n, "predecessor: %s -> %s" % (
            o.compact if o else "[None]", p.compact)

    def succ(n, o, s):
        print "  Peer", n, "successor:   %s -> %s" % (
            o.compact if o else "[None]", s.compact)

    def rem(n, r):
        print "  Peer", n, "removed:    %s" % r.compact

    print "  Created peer:", peer
    peer.on_new_predecessor = lambda o, p, peer=peer: pred(peer, o, p)
    peer.on_new_successor   = lambda o, s, peer=peer: succ(peer, o, s)
    peer.on_remove          = lambda r, peer=peer: rem(peer, r)
    peers.append(peer)

root_index = random.randint(0, len(peers) - 1)
root = peers[root_index]
print "Choosing peer #%d as the root: %s" % (root_index, root)

connected = [peers[root_index]]     # gotta start somewhere
unconnected = list(peers)
unconnected.remove(connected[0])

while unconnected:
    peer = random.choice(unconnected)
    root = random.choice(connected)

    print "Joining peer %s to network via %s" % (peer, root)
    unconnected.remove(peer)
    peer.join_ring(root.chord_addr)
    connected.append(peer)

sleep_time = PEER_COUNT * 10
print "Waiting some time for stabilization (%ds)..." % sleep_time
time.sleep(sleep_time)

print "Full peer dump:"
for peer in peers:
    print peer

print "Ensuring there are no independent loops."
peermap = {int(n.hash): n for n in peers}
pprint.pprint(peermap)
all_loops = []

while set(sum(map(list, all_loops), [])) != set(peermap.keys()):
    viable, seen = [
        node for node in peers \
        if int(node.hash) not in sum(map(list, all_loops), [])
    ], []

    loops = set()
    stack = [random.choice(viable)]
    while stack:
        def find(n):
            if int(n.hash) not in peermap:
                import pdb; pdb.set_trace()
            return peermap[int(n.hash)]

        node = stack.pop(0)
        loops.add(int(node.hash))
        if node.successor:
            loops.add(int(node.successor.hash))
            if node.successor.hash not in seen:
                stack.append(find(node.successor))
                seen.append(node.successor.hash)

        if node.predecessor:
            loops.add(int(node.predecessor.hash))
            if node.predecessor.hash not in seen:
                stack.append(find(node.predecessor))
                seen.append(node.predecessor.hash)

    all_loops.append(loops)

if len(all_loops) > 1:
    print "  FAILED! Found multiple network loops."
    print "  Loops:"
    for n, loop in enumerate(all_loops):
        print "    - Loop %d" % n
        for peer in loop:
            print "      %s" % peermap[peer]
        print "    ========="
    sys.exit(1)

print "Performing network validation..."
NodeDist = collections.namedtuple("NodeDist", "node dist")
for peer in connected:
    calc_successor = peer._find_closest_peer_moddist(int(peer.hash), set([peer]))
    print "    For the peer", peer
    print "      The calculated successor was", int(calc_successor.hash)
    print "      The actual successor is", int(peer.successor.hash)

    if not peer.successor or calc_successor.hash != peer.successor.hash:
        print "    FAILED! Expected %d, got %d: %s" % (calc_successor.hash,
              peer.successor.hash if peer.successor else 0, peer)
    else:
        print "    PASSED!"

raw_input("waiting for input...")

for peer in peers:
    peer.processor.stop_running()
    peer.listen_thread.stop_running()
    peer.stable.stop_running()
    peer.listener.close()
"""
