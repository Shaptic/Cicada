"""
An stripped-down implementation of the Chord protocol.

 Description
=============
The protocol is used in Cicada in order to traverse a selection of IP addresses
when communicating between two particular ones. In other words, all of the peers
in a network form a Chord ring; when two of those peers wish to communicate,
they use Chord's "lookup" algorithm to actually route the data.

 Example
=========
Suppose we have the following network of peers, arranged in a Chord ring:

            6 -- 7
           /      \
          4        1
           \      /
            3 -- 2

Now, Peer 3 wants to talk to Peer 7. According to the Chord protocol, Peer 3
will have the following finger table (that is, direct connections): 4, 6, 1. In
order to communicate with 7, Peer 3 performs a Chord lookup on 7. This gives us
the peer we *do* know about that immediately precedes 7 -- in this case, Peer 6.
Peer 3 sends a message to Peer 6 with intent to Peer 7. Peer 6 has a direct path
to Peer 7 in his [triggered] finger table; he can relay the message directly.

NOTE: This is what's called "recursive routing." The alternative is "iterative
      routing," in which Peer 6 responds to Peer 3 with Peer 7's address, rather
      than routing it himself.

 Broadcasts
============
With this network, broadcast messages can be distrbuted *extremely* fast and
with optimally minimal overhead. If every peer sends the messages to all of its
fingers (i.e. direct neighbors), the broadcast will be done with O(log n)
complexity across all nodes; this is a huge improvement over the standard O(n^2)
complexity inherent to P2P.

 Security
==========
As seen in the example, if Peer 6 forwards to Peer 7, it will see the content of
the message. This can be solved with asymmetric cryptography established between
Peer 3 and Peer 7, but if Peer 6 is involved with forwarding (and even relaying
address information, in the iterative case), he can still inject data and form
independent encryption with both parties. As a result, this protocol should
ideally be used in a trustworthy environment, or only perform encrypted
communication between direct peers (safe! no MitM), or with established
encryption (specifically, peer-specific secret keys) beforehand.

 References
============
https://pdos.csail.mit.edu/papers/chord:sigcomm01/chord_sigcomm.pdf
https://en.wikipedia.org/wiki/Chord_project
https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange

 Todo List
===========
[ ] Allow a Chord node to join a ring correctly.
[*] Threading for stabilization routine.
[ ] Design and implement remote nodes and rings.
[ ] Underlying p2p socket protocol.
"""

import sys
import time
import math
import random
import string
import threading

import pygame

import hashring
import search
from   utils import *

class Stabilizer(threading.Thread):
    """ Performs the Chord stabilization algorithm on a particular node. """
    def __init__(self, node):
        super(Stabilizer, self).__init__()
        self.node = node
        self.running = True

    def run(self):
        while self.running:
            print "'THREAD: Stabilizing for:'"
            print "'THREAD:", self.node, "'"
            self.node.stabilize()
            time.sleep(500)

class ChordNode(object):
    """ Represents any Chord node.

    There are certain properties -- such as the data hash -- which can be
    computed locally. All other properties may involve network communication, so
    we throw errors on those.
    """

    def __init__(self, data):
        super(ChordNode, self).__init__()
        #
        # All Chord nodes exist in their own "ring" on initialization. They have
        # an empty finger table (save themselves) and no predecessor reference.
        #
        self.data = data
        self.hash = hashring.pack_string(hashring.chord_hash(data))
        self.predecessor = None
        self.fingers = hashring.FingerTable(self)

    def joinRing(self, homie):
        """ Joins a Chord ring via a node in the ring. """
        raise NotImplementedError

    def nodeJoined(self, node):
        """ Receives a join from a node outside of the ring. """
        raise NotImplementedError

    def stabilize(self):
        """ Runs the Chord stabilization algorithm. """
        raise NotImplementedError

    def finger(self, i):
        assert len(self.fingers) <= hashring.BITCOUNT, "Finger table too long!"
        return self.fingers.finger(i)

    def pr(self, *args):
        print "%s | %s" % (str(int(self))[:8], ' '.join([ str(x) for x in args ]))

    @property
    def successor(self):
        assert self.fingers.realLength >= 1, "successor: node is isolated!"
        return self.finger(0).node

    def __repr__(self): return str(self)
    def __int__(self):  return self.hash
    def norecstr(self): return "<%s | hash=%s>" % (self.data, str(int(self))[:8])
    def __str__(self):  return "%s,pred=%s>" % (
        self.norecstr()[:-1],
        self.predecessor.norecstr() if self.predecessor is not None else "None")

class RemoteChordNode(ChordNode):
    """ Represents a remote Chord node in the hash ring.

    The primary purpose of this object is to handle communication from a local
    node to a remote node. It will cache properties within itself, but will
    perform a remote lookup otherwise.

    For example, accessing `RemoteChord.successor` MAY return a current value,
    but may require actual network communication to determine the successor,
    which is then cached.
    """
    pass

class LocalChordNode(ChordNode):
    """ Represents the current local node in the Chord hash ring.

    Specifically, this means the node exists *on this machine* and that no
    remote lookups or network communication is necessary.
    """
    def __init__(self, data):
        super(LocalChordNode, self).__init__(data)

    def addNode(self, node):
        """ Adds a node to the internal finger table.

        This means proper ordering in the finger table with respect to the
        node's hash value.
        """
        if isinstance(node, (list, tuple)):
            for x in node: self.addNode(x)

        assert isinstance(node, ChordNode), \
               "addNode: not a ChordNode object!"

        self.fingers.insert(node)

    def joinRing(self, homie):
        """ Joins a Chord ring using a specified node as its "entry".

        We use the stabilization technique outlined in the Chord paper, which
        means that a join only involves asking our homie for our immediate
        successor. Then, we set that to be our successor.
        """
        assert self.fingers.realLength <= 1, "joinRing: existing nodes!"
        assert self.predecessor is None,     "joinRing: predecessor set!"

        self.predecessor = None
        succ = homie.fingers.findSuccessor(self.hash)   # our would-be successor
        if succ is None:        # our homie is the only node!
            succ = homie
        self.addNode(succ)      # add successor to our own finger table
        succ.nodeJoined(self)   # notify successor that we joined to them

        assert self.successor == succ, "joinRing: successor not set!"

    def nodeJoined(self, homie):
        """ Receives a HELLO message from a node previously outside the ring.

        Chord specifies that this occurs when a new node joins the ring and
        chooses us as its successor. Thus, we use this node to (potentially)
        establish our predecessor.

        If it's our first node, though, it also gets added to the finger table!
        """
        assert isinstance(homie, ChordNode), "nodeJoined: invalid node!"

        # Always add node, because it could be better than some existing ones.
        self.addNode(homie)

        # Sanity check that the first node is our successor.
        if self.fingers.realLength <= 1:
            assert self.successor == homie, "nodeJoined: first node not set!"

        # Is this node closer to us than our existing predecessor?
        if self.predecessor is None or \
           hashring.Finger(self.predecessor.hash, self.hash).isWithin(homie.hash):
            self.predecessor = homie

    def stabilize(self):
        """ Runs the stabilization algorithm.

        Stabilizing means asking our successor, n, "for the successor's
        predecessor p, and decid[ing] whether p should be [our] successor
        instead." Then, we tell n's successor about n. That way, the successor
        can learn about n if it didn't already know in the first place.
        """
        print "stabilizing"
        print self
        print self.predecessor
        print self.successor
        print self.successor.predecessor
        print self.fingers

        x = self.successor.predecessor

        # If our successor doesn't *have* a predecessor, tell them about us, at
        # least! That way, the ring is linked.
        if x is None:
            self.successor.notify(self)
            return

        # We HAVE to use an open-ended range check, because if our successor's
        # predecessor is us (as it would be in the normal case), we'd be setting
        # us as our own successor!
        if self.fingers.local.isWithin_open(x.hash):
            self.fingers.setSuccessor(x)
        self.successor.notify(self)

    def fixFingers(self):
        """ This ensures that the finger table is current.
        """
        index = random.randint(1, len(self.fingers) - 1)
        thumb = self.finger(index)
        if thumb.node is None:
            return

        self.pr("fixFingers: fingers are\n%s" % self.fingers)
        raw_input("fixer")
        thumb.node = self.fingers.findSuccessor(thumb.start)
        self.pr("fixFingers: fingers are now\n%s" % self.fingers)

    def notify(self, node):
        """ Determine whether or not a node should be our predecessor.
        """
        self.pr("notify: trying", node)
        if self.predecessor is None or \
           Finger(self.predecessor.hash, self.hash).isWithin(node):
            self.predecessor = node

        assert self.predecessor != self, "notify: set self as predecessor!"

def main():
    address_ring = [
        ("192.168.0.1", 2016 + i) for i in xrange(10)
    ]

    nodes = sorted([
        LocalChordNode("%s:%d" % _) for _ in address_ring
    ], key=lambda x: x.hash)

    return nodes

if __name__ == "__main__":
    # Establish a list of independent nodes.
    ring = main()
    print '\n'.join([ str(x) for x in ring ])
    print

    # We decide to begin the ring with the first node.
    root = ring[0]
    print "Root:"
    print root
    print root.fingers

    st = Stabilizer(root)
    # st.start()

    # Add nodes to the ring and ensure finger tables are accurate.
    # for i in xrange(1, 4):#len(ring)):
    #     print "Joining node to root:"
    #     print ring[i]
    #     print ring[i].fingers
    #     ring[i].joinRing(root)
    #     root.fixFingers()
    #     root.stabilize()
    #     ring[i].stabilize()

    st.running = False
    # st.join(1000)

    print "Done"
    print root.fingers
