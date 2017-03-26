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

class Interval(object):
    """ Represents an interval [a, b) in a modulus ring.
    """
    def __init__(self, start, end, mod=HASHMOD):
        self.modulus = mod
        self.interval = (start, end)

    def isWithin(self, x):
        """ Is `x` within [start, end)? """
        if self.end < self.start:   # interval wraps around mod boundary
            return utils.in_range(x, self.start, self.modulus) or \
                   utils.in_range(x, 0, self.end)

        return utils.in_range(x, *self.interval)

    def isWithinOpen(self, x):
        """ Is `x` within (start, end)? """
        if self.end < self.start:   # interval wraps around mod boundary
            return utils.in_range(x, self.start + 1, self.modulus) or \
                   utils.in_range(x, 0, self.end)

        return utils.in_range(x, self.start + 1, self.end)

    def isWithinClosed(self, x):
        """ Is `x` within [start, end]? """
        if self.end < self.start:   # interval wraps around mod boundary
            return utils.in_range(x, self.start, self.modulus) or \
                   utils.in_range(x, 0, self.end + 1)

        return utils.in_range(x, self.start, self.end + 1)

    @property
    def start(self): return self.interval[0]

    @property
    def end(self): return self.interval[1]

    def __repr__(self): return str(self)
    def __str__(self):
        return "[%d, %s)" % (self.start, self.end)

class Finger(Interval):
    """ Represents a single entry in a finger table.
    """
    def __init__(self, start, end, node=None, mod=HASHMOD):
        super(Finger, self).__init__(start, end, mod)
        self.node = node    # node to contact regarding keys in the interval

    def __repr__(self): return str(self)
    def __str__(self):
        return "%s | %s" % (Interval.__str__(self), self.node)

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
        self.seenNodes = set()
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
        self.seenNodes.add(node)

        for i, f in enumerate(self.entries):
            # If this interval doesn't have a node associated with it
            #   OR
            # This node is closer to the start of the interval than the existing
            # node.
            if f.node is None or (
               moddist(f.start, node.hash) < \
               moddist(f.start, f.node.hash)):
                f.node = node

    def remove(self, node):
        """ Removes an existing node from the finger table.

        If possible, the finger table entry will then point to the next
        available node.

        For example, removing <3> from the existing finger table: [
            [0, 3)  -> <3>,
            [3, 7)  -> <4>,
            [8, 15) -> <4>,
        ] should result in <4> for all intervals.

        There are a few scenarios to consider:
            - Removal of entries UP TO the end of the table.
            - Removal of entries PAST the end of the table (i.e. a segment
              within the ring, wrapping around the modulus).
            - Removal of entries WITHIN the table without wrapping (this is
              the "normal" case).

        Each of these mean the same action: the first entry that follows the
        removed ones is the new successor node.
        """
        self.seenNodes.discard(node)

        removed = {}    # { index: cleaned node }
        for i, f in enumerate(self.entries):
            if f.node is node:
                print "removing", f
                removed[i] = f
                f.node = None

        # TODO: Optimize this, because they should all be the same?
        print "fingers are now"
        print self
        for index, entry in removed.iteritems():
            repl = self.findSuccessor(entry.start)
            print "replacing with", repl
            print "based on", entry
            self.entries[index].node = repl

    def findSuccessor(self, value):
        """ Finds the successor node for a particular value. """
        return self.findPredecessor(value).successor

    def findPredecessor(self, value):
        """ Finds the predecessor for a particular value. """
        start = self.root
        if start.successor is None:     # no fingers yet
            return start

        tmpEntry = Interval(start.hash, start.successor.hash, self.modulus)
        while not tmpEntry.isWithinClosed(value):
            start = self.lookupPreceding(value)
            tmpEntry = Interval(start.hash, start.successor.hash, self.modulus)
        return start

    def lookupPreceding(self, value):
        """ Finds the finger table entry that comes before the given value.
        """
        for i in xrange(len(self) - 1, -1, -1):
            n = self.finger(i).node
            if Interval(self.root.hash, value, self.modulus).isWithinOpen(n.hash):
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
        """ Returns the number of unique nodes in the finger table. """
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
          How do you insert things into it efficiently? Maybe use a hash-map
          of ranges? That is, { 1: node (implies [1, 5)), 5: node, ... }
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
