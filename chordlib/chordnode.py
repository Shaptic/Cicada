""" Outlines a base class for a Chord node object.
"""

import threading
import socket
import random
import time

from chordlib import L
from chordlib import commlib
from chordlib import fingertable
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
        self.node.fix_fingers()


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
        self.predecessor = None
        self.chord_addr = (socket.gethostbyname(listener_addr[0]),
                           listener_addr[1])
        self.fingers = fingertable.FingerTable(self)

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
