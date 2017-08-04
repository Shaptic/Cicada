""" Defines hashing functions and the Chord finger table.
"""

import hashlib

from chordlib import search
from chordlib import utils, L


HASHFN = hashlib.md5#hashlib.sha256
def chord_hash(data):
    return HASHFN(data).digest()[:2]


HASHLEN = len(chord_hash("0"))
BITCOUNT = HASHLEN * 8
HASHMOD  = 2 ** BITCOUNT


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
            self._hash_str  = chord_hash(self._value)
            self._hash_ints = Hash.pack_hash(self._hash_str)

        elif isinstance(hashed, str):
            self._hash_str  = hashed
            self._hash_ints = Hash.pack_hash(hashed)

        elif isinstance(hashed, Hash):  # copy
            self._hash_str  = str(hashed)
            self._hash_ints = tuple(hashed.parts)
            self._value = hashed.value

        else:
            raise TypeError("Expected value or (int, str, Hash), got: "
                "value='%s',hashed='%s'" % (value, hashed))

        assert str(self) == Hash.unpack_hash(self.parts), \
            "Unpacked hash must match direct hash!"

        assert len(str(self)) == HASHLEN, \
            "Invalid hash size: %s" % str(self)

    @property
    def value(self):
        return self._value

    @property
    def parts(self):
        return self._hash_ints

    def __int__(self):
        return sum([
            i << (32 * j) for j, i in enumerate(self.parts[::-1])
        ]) % HASHMOD

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
        return self < other and self == other

    def __ge__(self, other):
        return self > other and self == other

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
        if len(hash_chunks) != int(HASHLEN / 4):
            raise ValueError("expected %d integers, got: %s" % (
                             HASHLEN % 4, hash_chunks))

        chunks = []
        for num in hash_chunks:
            # mask with 0xFF shifted by index and shifted back to be in 0-255
            chunk = ''.join([
                chr((num & (0xFF << (8 * i))) >> (8 * i)) \
                for i in xrange(3, -1, -1)
            ])
            chunks.append(chunk)

        return ''.join(chunks)


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
