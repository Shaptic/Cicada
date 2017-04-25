import random

from . import hashring
from . import utils
from . import node

class LocalChordNode(node.ChordNode):
    """ Represents the current local node in the Chord hash ring.

    Specifically, this means the node exists *on this machine* and that no
    remote lookups or network communication is necessary.
    """
    def __init__(self, data):
        super(LocalChordNode, self).__init__(data)

        # This socket is responsible for inbound connections (from new potential
        # nodes). It is always in an "accept" state in a separate thread.
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # This socket is used exclusively for joining a Chord ring. Once a node
        # has joined a ring, this reference is removed and the socket is just a
        # part of the peer list.
        self.joiner = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # These are all of the known direct neighbors in the Chord ring.
        self.peers = []

    @utils.listify
    def addNode(self, node):
        """ Adds a node to the internal finger table.

        This means proper ordering in the finger table with respect to the
        node's hash value.
        """
        self.pr("addNode:", str(self), str(node))
        assert isinstance(node, ChordNode), \
               "addNode: not a ChordNode object!"

        self.fingers.insert(node)

    @utils.listify
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
