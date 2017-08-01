""" Outlines a base class for a Chord node object.
"""

import threading
import socket
import random
import time

from chordlib import L
from chordlib import commlib
from chordlib import routing
from chordlib import utils as chutils


class Stabilizer(commlib.InfiniteThread):
    """ Performs the Chord stabilization algorithm on a particular node.
    """

    def __init__(self, node):
        super(Stabilizer, self).__init__(name="StabilizerThread")
        self.node = node

    def _loop_method(self):
        self.sleep = random.randint(3, 10)
        self.node.stabilize()
        # self.node.fix_fingers()


class ChordNode(object):
    """ Represents any Chord node.

    There are certain properties -- such as the data hash -- which can be
    computed locally. All other properties may involve network communication, so
    we don't define those.
    """

    def __init__(self, node_hash, listener_addr):
        """ Initializes internal structures.

        All Chord nodes exist in their own "ring" on initialization. They have
        an empty finger table and no predecessor reference.

        :listener_addr  a 2-tuple (address, port) pair describing the address
                        on which the node is listening for new connections
        """
        super(ChordNode, self).__init__()

        self._hash = node_hash
        self.chord_addr = (socket.gethostbyname(listener_addr[0]),
                           listener_addr[1])
        self.fingers = routing.RoutingTable(self)
        self._predecessor = None

    def add_node(self, node):
        """ Adds a node to the internal finger table.

        This means proper ordering in the finger table with respect to the
        node's hash value.
        """
        if not isinstance(node, ChordNode):
            raise TypeError("expected ChordNode, got %s" % repr(node))

        L.debug("add_node::self: %s", str(self))
        L.debug("add_node::node: %s", str(node))
        self.fingers.insert(node)

    def finger(self, i):
        return self.fingers.finger(i)

    @property
    def successor(self):
        return self.finger(0).node

    #
    # The way we handle predecessor nodes is special. As soon as the finger
    # table becomes valid, so does the predecessor. *But*, if someone sets the
    # predecessor property *and it's closer than the existing one*, it's
    # overwritten.
    #
    @property
    def predecessor(self):
        if not self._predecessor and self.finger(0).node is None:
            return None

        if self._predecessor:
            return self._predecessor

        # root is fallback of `lookup_preceding`
        lookup = self.fingers.lookup_preceding(int(self.hash) - 1)
        return None if lookup is self else lookup

    @predecessor.setter
    def predecessor(self, node):
        if node is self:
            import pdb; pdb.set_trace()
            raise ValueError("the fuck?")

        import pdb; pdb.set_trace()
        self.fingers.insert(node)

        m = self.fingers.modulus
        n, p, h = int(node.hash), int(self.predecessor.hash), int(self.hash)
        if routing.moddist(n, h, m) < routing.moddist(p, h, m):
            self._predecessor = node

    @property
    def hash(self):     return self._hash
    def __repr__(self): return str(self)
    def __str__(self):  return "<ChordNode | %s:%d>" % self.chord_addr


def walk_ring(root, max_count=10, on_node=lambda x: None):
    """ Walks a Chord ring starting from the root via successor pointers.
    """
    count = 0
    start = root
    next_node = start.successor

    yield start
    while next_node is not None and \
          root != next_node and \
          count < max_count:   # so we don't do it too much if there's an error
        yield next_node
        on_node(next_node)
        next_node = next_node.successor
        count += 1
