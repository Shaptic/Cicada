from   hashlib import sha1

import search
import utils

USED = 0
def chord_hash(data):
    global USED
    USED += 1
    return USED
    # return sha1(data).digest()

def pack_string(data):
    """ Turns a string into its unique numeric representation.

    This will pack a string into a binary value by summing each individual
    character appropriately shifted. For example,

        "HI" is converted to 'H' + ('I' << 8), where each character is the ASCII
        digit equivalent.

    Of course, long strings become incredibly large numbers. Thus, things must
    be batched. Thankfully, Python _supports_ incredibly large numbers, so you
    _can_ go to an arbitrary length, but I don't recommend it.
    """
    if isinstance(data, int):
        return data

    total = 0
    for i, c in enumerate(data):
        total += ord(c) << (8 * i)
    return total

BITCOUNT = 4# len(chord_hash("0")) * 8
HASHMOD  = 2 ** BITCOUNT

def khash(k):
    return (2 ** k) % HASHMOD

def moddist(a, b, m=HASHMOD):
    """ Finds the distance FROM a TO b in a modulo ring of size m. """
    if b >= a: return b - a
    return (m - a) + b

class Finger(object):
    """ Represents a single entry in a finger table.
    """
    def __init__(self, start, end, node=None, mod=HASHMOD):
        self.modulus = mod
        self.interval = (start, end)
        self.node = node    # node to contact regarding keys in the interval

    def isWithin(self, x):
        if self.end < self.start:   # interval wraps around mod boundary
            return utils.in_range(x, self.start, self.modulus) or \
                   utils.in_range(x, 0, self.end)

        return utils.in_range(x, *self.interval)

    def isWithin_open(self, x):
        if self.end < self.start:   # interval wraps around mod boundary
            return utils.in_range(x, self.start + 1, self.modulus) or \
                   utils.in_range(x, 0, self.end)

        return utils.in_range(x, self.start + 1, self.end)

    def isWithin_closedright(self, x):
        if self.end < self.start:   # interval wraps around mod boundary
            return utils.in_range(x, self.start, self.modulus) or \
                   utils.in_range(x, 0, self.end + 1)

        return utils.in_range(x, self.start, self.end + 1)

    @property
    def start(self):
        return self.interval[0]

    @property
    def end(self):
        return self.interval[1]

    def __repr__(self): return str(self)
    def __str__(self):
        return "[%d, %d) | %s" % (self.start, self.end, self.node)

class FingerTable(object):
    """ Establishes a finger table for a particular node.

    The finger table is a list that is rotated around the root node (that is,
    the node this table is established for). On initialization, it's established
    to match the size of the bit-length of the hash (SHA1 is 128 bits).

    TODO: Optimize this.
    """

    def __init__(self, node, bitcount=BITCOUNT):
        """ Initializes the finger table with 2^i intervals around the root.

        >>> from collections import namedtuple
        >>> cn = namedtuple("ChordNode", "hash")
        >>> ft = FingerTable(cn(1), 4)   # Create a 4-bit, 16-node ring.
        >>> print ft
        [ [2, 3) | None,
          [3, 5) | None,
          [5, 9) | None,
          [9, 1) | None ]
        >>> for _ in [ 3, 7, 0, 2 ]: ft.insert(cn(_))
        >>> print ft
        [ [2, 3) | ChordNode(hash=2),
          [3, 5) | ChordNode(hash=3),
          [5, 9) | ChordNode(hash=7),
          [9, 1) | ChordNode(hash=0) ]
        >>> ft.insert(cn(6))    # test regular distance
        >>> ft.insert(cn(14))   # test mod distance
        >>> ft.insert(cn(15))   # ensure no-op
        >>> print ft
        [ [2, 3) | ChordNode(hash=2),
          [3, 5) | ChordNode(hash=3),
          [5, 9) | ChordNode(hash=6),
          [9, 1) | ChordNode(hash=14) ]
        """

        self.modulus = 2 ** bitcount
        self.entries = [
            Finger((node.hash + 2 ** i) % self.modulus,
                   (node.hash + 2 ** (i + 1)) % self.modulus,
                   None, self.modulus) \
            for i in xrange(bitcount)
        ]

        self.root = node
        self.local = Finger(self.entries[-1].end, self.root, self.root)

    def insert(self, node):
        """ Adds a node to the finger table if it's better than any successors.

        TODO: Improve O(n) insertion.
        """
        for i, f in enumerate(self.entries):
            # If this interval doesn't have a node associated with it
            #   OR
            # This node is closer to the start of the interval than the existing
            # node.
            start = (self.root.hash + (2 ** i)) % self.modulus
            if f.node is None or (
               moddist(f.start, node.hash) < \
               moddist(f.start, f.node.hash)):
                f.node = node

    def findSuccessor(self, value):
        """ Finds the successor node for a particular value. """
        return self.findPredecessor(value).successor

    def findPredecessor(self, value):
        """ Finds the predecessor for a particular value. """
        start = self.root
        tmpEntry = Finger(start.hash, start.successor.hash)
        while not tmpEntry.isWithin_closedright(value):
            start = self.lookupPreceding(value)
            tmpEntry = Finger(start.hash, start.successor.hash)
        return start

    def lookupPreceding(self, value):
        """ Finds the finger table entry that comes before the given value.
        """
        for i in xrange(len(self), -1, -1):
            n = self.finger(i).node
            if n.isWithin_open(self.root.hash, value):
                return n
        return self.root

    def setSuccessor(self, node):
        self.successor.node = node

    def finger(self, i):
        return self.entries[i]

    @property
    def successor(self):
        return self.finger(0)

    @property
    def realLength(self):
        return len(set([ self.finger(i).node for i in xrange(len(self)) ]))

    def __len__(self):  return len(self.entries)
    def __repr__(self): return str(self)
    def __str__(self):
        return "[ %s ]" % ",\n  ".join([
            str(self.finger(i)) for i in xrange(len(self))
        ])

def optimizeFingerTable(fingers):
    """ Compresses a finger table by merging intervals with the same successor.
    TODO: Perform this optimization in-place? Is this even *necessary*?
    """
    if not fingers: return fingers

    merged = []
    maxlen = len(fingers) - 1

    inspect = fingers[0]
    merged_start = inspect.start
    merged_end = inspect.end

    for old in xrange(0, maxlen):
        if fingers[old + 1].node == inspect.node:
            merged_end = fingers[old + 1].end
        else:
            merged.append(Finger(merged_start, merged_end, inspect.node))
            inspect = fingers[old + 1]

    return merged

class HashRing(object):
    """ Manages the Chord hash ring relative to a node.

    A prerequisite for the Chord protocol is the ability to create a "hash
    ring," which is a sorted list of hash values that are pivoted around a
    modulo -- the maximum hash value.

            6 -- 7
           /      \
          4        1
           \      /
            3 -- 2

    Imagine that a particular node hashes to 4. Then, it's communication
    neighbors (finger table, in Chord protocol language) could be, for example,
    [7, 2, 3]. When a new node is added to the ring, and it, for example, hashes
    to 8, it has to be correctly inserted at the index 1 -- [7, 8, 2, 3].

    There are many "weird" cases, and these are all handled in this object. This
    is essentially just a wrapper around a rotated list, with the rotation
    itself being emulated.
    """

    def __init__(self, node):
        self.base_node = node
        self.nodes = [ self.base_node ]

    def insert(self, node):
        """ Inserts a node in the proper position in the ring. """
        pred = search.successor(node.hash, self.nodes, packed=True)
        self.nodes.insert(pred, node)
        assert sorted(self.nodes, key=lambda x: x.hash) == self.nodes

    def finger(self, j):
        """ Returns the j-th node in the ring, w.r.t. the root node. """
        base   = self.index
        length = len(self.nodes)

        if j >= length:
            print "[-] Finger table:"
            print self
            raise IndexError("Querying too many fingers: %d" % j)

        if base + j >= length:  # we are wrapping past the end
            j -= length - base
            return self.nodes[j]
        return self.nodes[base + j]

    def plookup(self, node):
        """ Finds the predecessor to the node in the finger table.

        If the node exists, it's returned. Otherwise, it's the nearest node that
        comes before it in the hash ring.
        """
        return self._lookup(node, search.predecessor)

    def slookup(self, node):
        """ Finds the successor to the node in the finger table.

        If the node exists, it's returned. Otherwise, it's the first node that
        comes after it in the hash ring.
        """
        return self._lookup(node, search.successor)

    def _lookup(self, node, fn):
        idx = fn(node.hash, self.nodes)

        # If the node comes before the root node, we need to offset the index
        # such that .finger(idx) == index.
        #
        # If the node comes after the root, we just subtract the root node
        # index. If it comes before, we add the distance from the root node to
        # the "end" of the ring.
        if idx < self.index:
            return idx + (len(self.nodes) - self.index)
        return idx - self.index

    @property
    def index(self):
        return self.nodes.index(self.base_node)

    def __len__(self):  return len(self.nodes)
    def __repr__(self): return str(self)
    def __str__(self):
        return "[ %s ]" % ('\n  '.join([
            str(x.hash) if x != self.base_node else "%s*" % str(x.hash) \
            for x in self.nodes
        ]))
