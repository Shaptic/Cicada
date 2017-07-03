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
    """ Performs the Chord stabilization algorithm on a particular node. """
    def __init__(self, node):
        super(Stabilizer, self).__init__(name="StabilizerThread")
        self.node = node

    def _loop_method(self):
        time.sleep(random.randint(3, 10))
        self.node.stabilize()
        self.node.fix_fingers()


class ChordNode(object):
    """ Represents any Chord node.

    There are certain properties -- such as the data hash -- which can be
    computed locally. All other properties may involve network communication, so
    we throw errors on those.
    """

    def __init__(self, listener_addr):
        super(ChordNode, self).__init__()
        #
        # All Chord nodes exist in their own "ring" on initialization. They have
        # an empty finger table (save themselves) and no predecessor reference.
        #
        self.data = None
        self.predecessor = None
        self.fingers = fingertable.FingerTable(self)
        self.local_addr = (socket.gethostbyname(listener_addr[0]),
                           listener_addr[1])

    def add_node(self, node):
        """ Adds a node to the internal finger table.

        This means proper ordering in the finger table with respect to the
        node's hash value.
        """
        L.debug("add_node::self: %s", str(self))
        L.debug("add_node::node: %s", str(node))
        assert isinstance(node, ChordNode), "add_node: not a ChordNode object!"

        self.fingers.insert(node)

    def join_ring(self, address):
        """ Joins a Chord ring via a node in the ring. """
        raise NotImplementedError

    def stabilize(self):
        """ Runs the Chord stabilization algorithm. """
        raise NotImplementedError

    def finger(self, i):
        assert len(self.fingers) <= fingertable.BITCOUNT, "Finger table too long!"
        return self.fingers.finger(i)

    @property
    def successor(self):
        assert self.fingers.real_length >= 1, "successor: node is isolated!"
        return self.finger(0).node

    @property
    def hash(self):
        return self._hash   # undefined in this class

    def __repr__(self): return str(self)


def walk_ring(root, maxcount=10):
    count = 0
    start = root
    next_node = start.successor

    yield start
    while next_node is not None and \
          root != next_node and \
          count < maxcount:   # so we don't do it too much if there's an error
        yield next_node
        nextOne = next_node.successor
        count += 1


def print_ring(root):
    for node in walk_ring(root):
        print node
