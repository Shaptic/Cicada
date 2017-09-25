""" Defines hashing functions and the Chord finger table.
"""

import math
import enum
import hashlib

from chordlib import search
from chordlib import utils, L


HASHFN = hashlib.md5#hashlib.sha256
def chord_hash(data):
    return HASHFN(data).digest()[:2]


HASHLEN  = len(chord_hash("0"))
CHUNKLEN = int(math.ceil(HASHLEN / 4.0))
BITCOUNT = HASHLEN * 8
HASHMOD  = 2 ** BITCOUNT
HASHLEN  = utils.nextmul(len(chord_hash("0")), 4)


def khash(k, m):
    return (2 ** k) % m

def moddist(a, b, m):
    """ Finds the distance FROM a TO b in a modulo ring of size m. """
    if b >= a: return b - a
    return (m - a) + b


class Hash(object):
    """ Represents a hashed object with proper conversions between types.
    """
    def __init__(self, value="", hashed=""):
        """ Initializes the hash in one of two ways.

        Either you know the initial value, and the hash is computed, or you know
        the hashed value (and the initial value is by definition not
        determinable) and only that is stored.
        """
        if value and hashed:
            raise ValueError("Either pass a value or its hash.")

        self._value = value
        if self._value:
            self._hash_str  = chord_hash(self._value).rjust(HASHLEN, '\x00')
            self._hash_ints = Hash.pack_hash(self._hash_str)

        elif isinstance(hashed, str) and hashed:
            self._hash_str  = hashed
            self._hash_ints = Hash.pack_hash(hashed)

        elif isinstance(hashed, Hash):  # copy
            self._hash_str  = str(hashed)
            self._hash_ints = tuple(hashed.parts)
            self._value = hashed.value

        elif isinstance(hashed, (tuple, list)) and len(hashed) == CHUNKLEN:
            self._hash_str = Hash.unpack_hash(hashed)
            self._hash_ints = tuple(hashed)

        else:
            raise TypeError("Expected value or (int, str, iter, Hash), got: "
                "value='%s',hashed='%s'" % (value, hashed))

        assert str(self) == Hash.unpack_hash(self.parts), \
            "Unpacked hash must match direct hash!"

        assert len(str(self)) == HASHLEN, \
            "Invalid hash size: %s" % str(self)

        self._int_cache = sum([
            i << (32 * j) for j, i in enumerate(self.parts[::-1])
        ]) % HASHMOD

    @property
    def value(self):
        return self._value

    @property
    def parts(self):
        return self._hash_ints

    def __int__(self):
        return self._int_cache

    def __eq__(self, other):
        if isinstance(other, int):    return int(self) == other
        elif isinstance(other, str):  return str(self) == other
        elif isinstance(other, Hash): return int(self) == int(other)
        raise TypeError("expected int,str,Hash, got %s" % type(other))

    def __ne__(self, other):
        return not (self == other)

    def __lt__(self, other):
        for i in len(self.parts):
            if self.parts[i] < other.parts[i]:
                return True
            elif self.parts[i] > other.parts[i]:
                return False
        return False

    def __gt__(self, other):
        for i in len(self.parts):
            if self.parts[i] > other.parts[i]:
                return True
            elif self.parts[i] < other.parts[i]:
                return False
        return False

    def __le__(self, other):
        return self < other or self == other

    def __ge__(self, other):
        return self > other or self == other

    def __str__(self):  return self._hash_str
    def __repr__(self): return str(self)

    @staticmethod
    def pack_hash(data):
        """ Packs an output of the hashing function into a series of integers.
        """
        if len(data) != HASHLEN:
            raise ValueError("expected a hash, got something else? %s" % data)

        chunks = []
        for i in xrange(0, HASHLEN, 4):         # 4 bytes to an integer
            chunk = data[i : i + 4]
            # pack characters left to right, shifting a byte per index
            n = sum([ord(c) << 8 * x for x, c in enumerate(chunk[::-1])])
            chunks.append(n)

        return tuple(chunks)

    @staticmethod
    def unpack_hash(hash_chunks):
        """ Unpacks a series of integers into a hash string.
        """
        if len(hash_chunks) != CHUNKLEN:
            raise ValueError("expected %d integers, got: %s" % (
                             CHUNKLEN, hash_chunks))

        chunks = []
        for num in hash_chunks:
            # mask with 0xFF shifted by index and shifted back to be in 0-255
            chunk = ''.join([
                chr((num & (0xFF << (8 * i))) >> (8 * i)) \
                for i in xrange(3, -1, -1)
            ])
            chunks.append(chunk)

        return ''.join(chunks).ljust(HASHLEN, '\x00')

    @staticmethod
    def pack_int(long_value):
        """ Converts a > 32-bit integer into an array, smallest first.
        """
        parts = []
        while long_value > 0:
            nextval = long_value & 0xFFFFFFFF
            parts.append(int(nextval))
            long_value >>= 32
        return parts


class Interval(object):
    """ Represents an interval [a, b) in a modulus ring.
    """
    def __init__(self, start, end, mod=HASHMOD):
        self.modulus = mod
        self.interval = (start, end)

    def within(self, x):
        """ Is `x` within [start, end)? """
        x = int(x)  # convert from `Hash` object
        assert x < self.modulus, "checking un-%% value: %s/%d" % (x, HASHMOD)
        if self.end < self.start:   # interval wraps around mod boundary
            return utils.in_range(x, self.start, self.modulus) or \
                   utils.in_range(x, 0, self.end)

        return utils.in_range(x, *self.interval)

    def within_open(self, x):
        """ Is `x` within (start, end)? """
        x = int(x)  # convert from `Hash` object
        assert x < self.modulus, "checking un-%% value: %s/%d" % (x, HASHMOD)
        if self.end < self.start:   # interval wraps around mod boundary
            return utils.in_range(x, self.start + 1, self.modulus) or \
                   utils.in_range(x, 0, self.end)

        return utils.in_range(x, self.start + 1, self.end)

    def within_closed(self, x):
        """ Is `x` within [start, end]? """
        x = int(x)  # convert from `Hash` object
        assert x < self.modulus, "checking un-%% value: %s/%d" % (x, HASHMOD)
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


class Route(Interval):
    """ Represents an `Interval` with an associated peer.
    """

    def __init__(self, start, end, peer, mod=HASHMOD):
        super(Route, self).__init__(start, end, mod)
        self.peer = peer

    def __repr__(self): return str(self)
    def __str__(self):
        return "[%d, %s) | %s" % (self.start, self.end, repr(self.peer))



class RoutingTable(object):
    """ Represents routing optimization table for a peer.

    We have a series of entries starting from the peer's hash value, with 2^i
    steps between each entry. These should be refreshed regularly from the peer
    itself.
    """

    class LookupState(enum.Enum):
        """ Indicates how closely we resolved a particular lookup value.
        """
        INVALID = 0     # the routing table is not in a good state
        LOCAL = 1       # resolved perfectly locally
        REMOTE = 2      # resolved to the nearest local neighbor, but they need
                        # to be asked for a closer resolution


    def __init__(self, root, mod=HASHMOD):
        self.mod = HASHMOD
        self.root = root

        self.length = int(math.ceil(math.log(self.mod, 2)))

        start = int(self.root.hash)
        self.routes = [
            Route((start + 2 ** i)       % self.mod,
                  (start + 2 ** (i + 1)) % self.mod,
                  None, self.mod) \
            for i in xrange(self.length)
        ]

    def lookup(self, value):
        """ Finds the closest successor peer of a value.
        """
        value = int(value)
        result, best = self.root, moddist(value, int(self.root.hash), self.mod)
        for peer in self.unique_iter(0):
            md = moddist(value, int(peer.hash), self.mod)
            if md < best:
                best = md
                result = peer
                if best == 0: break     # exact match

        return result

    def find_predecessor(self, value):
        """ Finds the nearest known predecessor peer for a value.

        The way the predecessor lookup works is this:
            - We pick a peer, starting with the root peer of this routing table.
            - If: value in (peer, peer.successor], that peer is the predecessor.
            - Otherwise, we delegate to `closest_preceding` to find the next-
              best preceding value.
            - This usually results in a "remote" value, meaning we will need to
              perform a remote lookup.
            - If not, go to step 2.

        Theoretically, we could make this a conditional rather than a loop, but
        because of the feasability that we could cache the routing tables of
        remote nodes, it won't always result in a remote lookup. This concept,
        though, will require a security review, since it may enable a single
        peer to gain way too much information about the rest of the network.

        :value      an integer or `Hash` value to perform a lookup on
        :returns    a 2-tuple of the resulting peer node and a
                    `RoutingTable.LookupState` indicating how well we could
                    resolve the lookup locally
        """
        value = int(value)              # consolidate to `int`
        if not self.root.successor:     # no valid entries yet
            return self.root, RoutingTable.LookupState.INVALID

        rv = self.root
        iv = Interval(int(rv.hash), int(rv.successor.hash), self.mod)
        if iv.within(value):
            return rv, RoutingTable.LookupState.LOCAL

        return self.closest_preceding(value), RoutingTable.LookupState.REMOTE

    def closest_preceding(self, value):
        value = int(value)
        for i in xrange(len(self.routes) - 1, -1, -1):
            iv = Interval(int(self.root.hash), value, self.mod)
            peer = self(i)
            if peer and iv.within_open(int(peer.hash)):
                return peer

        return self.root

    @property
    def successor(self):
        return self(0)

    def iter(self, start):
        yield self.routes[start]

        i = (start + 1) % len(self.routes)
        while i != start:
            yield self.routes[i]
            i = (i + 1) % len(self.routes)

    def unique_iter(self, start):
        """ Iterates over the unique, non-None peers in the routing table.
        """
        last = None
        for route in self.iter(start):
            if not route.peer: continue
            if route.peer == last:
                continue

            last = route.peer
            yield route.peer

    def __getitem__(self, i):
        return self.routes[i]

    def __setitem__(self, i, peer):
        for route in self.iter(i):
            if not route.peer:
                route.peer = peer
                continue

            md = moddist(route.start, int(peer.hash),       self.mod)
            cr = moddist(route.start, int(route.peer.hash), self.mod)
            if md <= cr and route.peer.chord_addr != peer.chord_addr:
                route.peer = peer

    def __len__(self):
        """ Returns the number of valid unique routing entries in the table.
        """
        return len(set(map(lambda r: r.peer, filter(lambda x: x, self.routes))))

    def __contains__(self, peer):
        for entry in self.routes:
            if entry.peer == peer:
                return True
        return False

    def __call__(self, i):
        """ Returns the first available peer for an interval.
        """
        for route in self.iter(i):
            if route.peer:
                return route.peer
