import threading
import socket
import random
import time

from . import communication
from . import hashring
from . import utils


class Stabilizer(communication.InfiniteThread):
    """ Performs the Chord stabilization algorithm on a particular node. """
    def __init__(self, node):
        super(Stabilizer, self).__init__()
        self.node = node

    def _loop_method(self):
        # print "'THREAD: Stabilizing for:'"
        # print "'THREAD:", self.node, "'"
        self.node.stabilize()
        self.node.fix_fingers()
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

    def join_ring(self, homie):
        """ Joins a Chord ring via a node in the ring. """
        raise NotImplementedError

    def node_joined(self, node):
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
