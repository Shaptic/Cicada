""" Outlines a base class for a Chord node object.
"""

import threading
import socket
import random
import time
import enum

from chordlib import L
from chordlib import commlib
from chordlib import routing
from chordlib import utils as chutils


class PeerState(enum.Enum):
    UNKNOWN = 0
    OPEN    = 1
    ONEWAY  = 2
    CLOSED  = 3


class Stabilizer(commlib.InfiniteThread):
    """ Performs the Chord stabilization algorithm on a particular node.
    """

    def __init__(self, node):
        super(Stabilizer, self).__init__(name="StabilizerThread")
        self.node = node

    def _loop_method(self):
        self.sleep = random.randint(3, 10)
        self.node.stabilize()


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

        self.hash = node_hash
        self.chord_addr = (socket.gethostbyname(listener_addr[0]),
                           listener_addr[1])
        self.predecessor = None
        self.successor = None
        self.state = PeerState.UNKNOWN

    def __repr__(self): return str(self)
    def __str__(self):
        return "[%s<-peer(%s:%d|hash=%d)->%s" % (
            str(int(self.predecessor.hash)) if self.predecessor else None,
            self.chord_addr[0], self.chord_addr[1], self.hash,
            str(int(self.successor.hash)) if self.successor else None)


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
