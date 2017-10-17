from ..packetlib import debug   as D
from ..packetlib import message as M
from ..chordlib  import routing as R

h = R.Hash(value="sender")
n = M.MessageContainer(M.MessageType.MSG_CH_NOTIFY, h,
                       data="hey babes\x77hey", sequence=2884)
print n; print
print repr(n.pack());
print "len=%d" % len(n.pack()); print
n.dump()
print
D.dump_packet(n.pack(), n.full_format())
assert n.pack() == n.unpack(n.pack()).pack()

import sys
import random
import string
from   ..chordlib.routing import chord_hash, Hash

HASH_COUNT = 1000
print "Running hashing test with %d hashes." % HASH_COUNT
for i in xrange(HASH_COUNT):
    start = ''.join([
        random.choice(string.lowercase) for _ in xrange(random.randint(10, 20))
    ])

    print "  Trying value=%s...\r" % start,
    h = Hash(value=start)
    assert Hash.pack_hash(str(h)) == h.parts, \
           "pack check failed for value=%s, hash=%s, calc=%s" % (
           start, h.parts, Hash.pack_hash(str(h)))

print
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

