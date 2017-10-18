""" Outlines a base class for a Chord node object.
"""

import threading
import socket
import random
import time
import enum

from ..chordlib import L
from ..chordlib import routing
from ..chordlib import utils as chutils


class Stabilizer(chutils.InfiniteThread):
    """ Performs the Chord stabilization algorithm on a particular node.
    """
    def __init__(self, peer):
        super(Stabilizer, self).__init__(name="StabilizerThread",
                                         pause=lambda: random.randint(3, 10))
        self.peer = peer

    def _loop_method(self):
        self.peer.stabilize()


class RouteOptimizer(chutils.InfiniteThread):
    """ Performs periodic successor lookups to fill out route table.
    """
    def __init__(self, peer):
        super(RouteOptimizer, self).__init__(name="RouteTableThread",
                                             pause=lambda: random.randint(2, 7))
        self.peer = peer

    def _loop_method(self):
        self.peer.fix_routes()


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

        :node_hash      a `routing.Hash` instance that is the unique ID of the
                        peer globally within the network
        :listener_addr  a 2-tuple (address, port) pair describing the address
                        on which the node is listening for new connections
        """
        super(ChordNode, self).__init__()

        self.hash = node_hash
        self.chord_addr = (socket.gethostbyname(listener_addr[0]),
                           listener_addr[1])
        self._predecessor = None
        self._successor = None

    @property
    def is_valid(self):
        raise NotImplementedError()

    @property
    def predecessor(self):
        return self._predecessor

    @property
    def successor(self):
        return self._successor

    @predecessor.setter
    def predecessor(self, pred):
        old = self._predecessor
        self._predecessor = pred
        self.on_new_predecessor(old, pred)

    @successor.setter
    def successor(self, succ):
        old = self._successor
        self._successor = succ
        self.on_new_successor(old, succ)

    @property
    def compact(self):
        return "%s:%d|hash=%s" % (self.chord_addr[0], self.chord_addr[1],
            str(int(self.hash)).rjust(len(str(routing.HASHMOD)), "0")[:6])

    def __repr__(self): return str(self)
    def __str__(self):
        return "[%s<-%s->%s]" % (
            str(int(self.predecessor.hash))[:6] if self.predecessor else None,
            self.compact,
            str(int(self.successor.hash))[:6]   if self.successor else None)

    def on_new_predecessor(self, old, new): pass
    def on_new_successor(self,   old, new): pass


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
