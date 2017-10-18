# Stress testing process:
#
#  - Create a bunch of arbitrary nodes.
#  - Connect them all randomly.
#  - Ensure that after some time, each one's successor pointer is as close as it
#    can be, and likewise for the predecessor pointer.
#
import time
import random
import collections
import unittest
import sys
sys.path.append(".")

from cicada.chordlib import localnode


PEER_COUNT = 25
class TestStressStabilization(unittest.TestCase):
    """ A test that rapidly joins a bunch of peers to a network and stabilizes.
    """
    def test_stress(self):
        peers = self._join_all()
        self._stabilize(peers)

        for peer in peers:
            peer.processor.stop_running()
            peer.listen_thread.stop_running()
            peer.stable.stop_running()
            peer.listener.shutdown()
            peer.listener.close()

    def _join_all(self):
        start_port = random.randint(10000, (2 ** 16) - PEER_COUNT - 1)
        peers = []
        for i in xrange(PEER_COUNT):
            address = ("localhost", start_port + i)
            peer = localnode.LocalNode("%s:%d" % address, address)

            # def pred(n, o, p):
            #     print "  Peer", n, "predecessor: %s -> %s" % (
            #         o.compact if o else "[None]", p.compact)

            # def succ(n, o, s):
            #     print "  Peer", n, "successor:   %s -> %s" % (
            #         o.compact if o else "[None]", s.compact)

            # def rem(n, r):
            #     print "  Peer", n, "removed:    %s" % r.compact

            # print "  Created peer:", peer
            # peer.on_new_predecessor = lambda o, p, peer=peer: pred(peer, o, p)
            # peer.on_new_successor   = lambda o, s, peer=peer: succ(peer, o, s)
            # peer.on_remove          = lambda r, peer=peer: rem(peer, r)
            peers.append(peer)

        root_index = random.randint(0, len(peers) - 1)
        root = peers[root_index]
        # print "Choosing peer #%d as the root: %s" % (root_index, root)

        connected = [peers[root_index]]     # gotta start somewhere
        unconnected = list(peers)
        unconnected.remove(connected[0])

        while unconnected:
            peer = random.choice(unconnected)
            root = random.choice(connected)

            # print "Joining peer %s to network via %s" % (peer, root)
            unconnected.remove(peer)
            peer.join_ring(root.chord_addr)
            connected.append(peer)

        return peers

    def _stabilize(self, peers):
        time.sleep(PEER_COUNT * 10)

        peermap = {int(n.hash): n for n in peers}
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
                    self.assertTrue(int(n.hash) in peermap)
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
            self.assertTrue(len(all_loops) == 1)

        # print "Performing network validation..."
        NodeDist = collections.namedtuple("NodeDist", "node dist")
        for peer in peers:
            calc_successor = peer._find_closest_peer_moddist(int(peer.hash), set([peer]))
            if not peer.successor or calc_successor.hash != peer.successor.hash:
                print "  FAILED! Expected %d, got %d: %s" % (calc_successor.hash,
                      peer.successor.hash if peer.successor else 0, peer)

            self.assertTrue(peer.successor)
            self.assertTrue(calc_successor.hash == peer.successor.hash)


if __name__ == '__main__':
    unittest.main()
