import packetlib.debug   as D
import packetlib.message as M

n = M.MessageContainer(M.MessageType.MSG_CH_NOTIFY, "hey babes\x77hey", 2884)
print n; print
print repr(n.pack());
print "len=%d" % len(n.pack()); print
n.dump()
print
D.dump_packet(n.pack(), n.full_format())

import sys
import random
import string
from   chordlib.routing import chord_hash, Hash

print "Running hashing test."
for i in xrange(1000):
    start = ''.join([
        random.choice(string.lowercase) for _ in xrange(random.randint(10, 20))
    ])

    print "  Trying value=%s..." % start
    h = Hash(value=start)
    assert Hash.pack_hash(str(h)) == h.parts, \
           "pack check failed for value=%s, hash=%s, calc=%s" % (
           start, h.parts, Hash.pack_hash(str(h)))

print "Hashing test passed."
print "All unit tests passed!"
print "Running stress test."

# Stress testing process:
#
#  - Create a bunch of arbitrary nodes.
#  - Connect them all randomly.
#  - Ensure that after some time, each one's successor pointer is as close as it
#    can be, and likewise for the predecessor pointer.
#
import sys
import time
import pprint
import random
import collections
import chordlib.localnode
import chordlib.routing

PEER_COUNT = 50
start_port = random.randint(0xB00B, (2 ** 16) - PEER_COUNT - 1)
peers = []
print "Creating %d peers..." % PEER_COUNT
for i in xrange(PEER_COUNT):
    address = ("localhost", start_port + i)
    peer = chordlib.localnode.LocalNode("%s:%d" % address, address)
    peers.append(peer)
    print "  Created peer:", peer

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
seen = []
loops = set()
stack = [peers[root_index]]
peermap = {int(n.hash): n for n in peers}
pprint.pprint(peermap)
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

if len(loops) != len(peers):
    print "  FAILED! Only found %d peers in this network." % len(loops)
    print "  Remainder:", [node for node in peers \
                           if int(node.hash) not in loops]
    sys.exit(1)

print "Performing network validation..."
NodeDist = collections.namedtuple("NodeDist", "node dist")
for peer in connected:
    network = [
        NodeDist(p, chordlib.routing.moddist(int(peer.hash), int(p.hash),
                                             chordlib.routing.HASHMOD)) \
        for p in connected if p != peer
    ]

    expected_successor = min(network, key=lambda x: x.dist).node
    if expected_successor.hash != peer.successor.hash:
        print "    FAILED! Expected %d, got %d: %s" % (
              expected_successor.hash, peer.successor.hash, peer)
    else:
        print "    PASSED!"

for peer in peers:
    peer.processor.stop_running()
    peer.listen_thread.stop_running()
    peer.stable.stop_running()
    peer.listener.close()
