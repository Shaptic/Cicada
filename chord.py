""" A stripped-down implementation of the Chord protocol.
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
            # print "'THREAD: Stabilizing for:'"
            # print "'THREAD:", self.node, "'"
            self.node.stabilize()
            self.node.fixFingers()
            time.sleep(random.randint(3, 8))

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
        self.stable = Stabilizer(self)
        self.stable.start()

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
        print "%03s | %s" % (str(int(self))[:8],
            ' '.join([ str(x) for x in args ]))

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

    @listify
    def addNode(self, node):
        """ Adds a node to the internal finger table.

        This means proper ordering in the finger table with respect to the
        node's hash value.
        """
        self.pr("addNode:", str(self), str(node))
        assert isinstance(node, ChordNode), \
               "addNode: not a ChordNode object!"

        self.fingers.insert(node)

    @listify
    def removeNode(self, node):
        """ Indicates a node has disconnected / failed in the Chord ring.
        """
        self.pr("removeNode:", str(self), str(node))
        assert isinstance(node, ChordNode), \
               "removeNode: not a ChordNode object!"

        self.fingers.remove(node)

        #
        # If this node used to be our successor, replace it with the next
        # available node. Likewise with the predecessor, except the previous
        # available node.
        #
        # If this was the last node in the ring (excluding us) this should
        # properly trigger the "first node" code path in `nodeJoined()`.
        #

        if self.successor is node:
            self.successor = self.fingers.findSuccessor(node.hash + 1)

        if self.predecessor is node:
            self.predecessor = self.fingers.findPredecessor(node.hash - 1)

    def joinRing(self, homie):
        """ Joins a Chord ring using a specified node as its "entry".

        We use the stabilization technique outlined in the Chord paper, which
        means that a join only involves asking our homie for our immediate
        successor. Then, we set that to be our successor.
        """
        self.pr("joinRing:", str(self), str(homie))

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
        self.pr("nodeJoined:", str(self), str(homie))

        assert isinstance(homie, ChordNode), "nodeJoined: invalid node!"

        # Always add node, because it could be better than some existing ones.
        self.addNode(homie)

        # Is this node closer to us than our existing predecessor?
        if self.predecessor is None or \
           hashring.Interval(self.predecessor.hash, self.hash).isWithin(homie.hash):
            self.predecessor = homie

    def stabilize(self):
        """ Runs the stabilization algorithm.

        Stabilizing means asking our successor, n, "for the successor's
        predecessor p, and decid[ing] whether p should be [our] successor
        instead." Then, we tell n's successor about n. That way, the successor
        can learn about n if it didn't already know in the first place.
        """
        if self.successor is None:  # nothing to stabilize, yet
            return

        # print "stabilizing"
        # print self
        # print self.predecessor
        # print self.successor
        # print self.successor.predecessor
        # print self.fingers

        x = self.successor.predecessor

        # If our successor doesn't *have* a predecessor, tell them about us, at
        # least! That way, the ring is linked.
        if x is None:
            self.successor.notify(self)
            return

        # We HAVE to use an open-ended range check, because if our successor's
        # predecessor is us (as it would be in the normal case), we'd be setting
        # us as our own successor!
        if self.fingers.local.isWithinOpen(x.hash):
            self.fingers.setSuccessor(x)
        self.successor.notify(self)

    def fixFingers(self):
        """ This ensures that the finger table is current.
        """
        index = random.randint(1, len(self.fingers) - 1)
        thumb = self.finger(index)
        if thumb.node is None:
            return

        # self.pr("fixFingers: fixing finger(%d)" % index)
        # self.pr("fixFingers: fingers are\n%s" % self.fingers)
        thumb.node = self.fingers.findSuccessor(thumb.start)
        # self.pr("fixFingers: fingers are now\n%s" % self.fingers)

    def notify(self, node):
        """ Determine whether or not a node should be our predecessor.
        """
        # self.pr("notify: trying", node)
        if self.predecessor is None or \
           hashring.Interval(self.predecessor.hash, self.hash).isWithin(node):
            self.predecessor = node

        assert self.predecessor != self, "notify: set self as predecessor!"

def walk_ring(root, maxcount=10):
    count = 0
    firstOne = root
    nextOne = firstOne.successor

    yield firstOne
    while nextOne is not None and \
          root != nextOne and \
          count < maxcount:   # so we don't do it too much if there's an error
        yield nextOne
        nextOne = nextOne.successor
        count += 1

def print_ring(root):
    for node in walk_ring(root):
        print node

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

    # Add nodes to the ring and ensure finger tables are accurate.
    # for i in xrange(1, 4):#len(ring)):
    #     print "Joining node to root:"
    #     print ring[i]
    #     print ring[i].fingers
    #     ring[i].joinRing(root)
    #     root.fixFingers()
    #     root.stabilize()
    #     ring[i].stabilize()

    print "Done"
    print root.fingers

    # for node in walk_ring(root):
    #     root.stable.join(1000)
