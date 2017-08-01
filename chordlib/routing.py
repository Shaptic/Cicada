""" Defines hashing functions and the Chord finger table.
"""

import hashlib

from chordlib import search
from chordlib import utils, L


HASHFN = hashlib.md5#hashlib.sha256
def chord_hash(data):
    import random, string
    return ''.join([ random.choice(string.letters) for _ in xrange(2) ])
    return HASHFN(data).digest()


HASHLEN = len(chord_hash("0"))
BITCOUNT = HASHLEN * 8
HASHMOD  = 2 ** BITCOUNT


def pack_string(data):
    """ Turns a string into its unique numeric representation.

    Packs a string into a binary value by summing each individual character,
    appropriately shifted. For example,

        "HI" is converted to 'H' + ('I' << 8), where each character is the ASCII
        digit equivalent.

    This assumes an ASCII charset because of the 8-bit-per-character factor.

    Of course, long strings become incredibly large numbers. Python does support
    arbitrarily large numbers, but I don't recommend using this function for
    very long strings.
    """
    if not isinstance(data, str):
        raise TypeError("Expected str, got %s" % str(type(data)))

    total = 0
    for i, c in enumerate(data):
        total += ord(c) << (8 * (len(data) - 1 - i))

    L.debug("Hash for %s -- %d", repr(data), total)
    return total

def unpack_string(val):
    """ Turns a numeric value into a string by treating every byte as a char.
    """
    string = ""
    while val > 0:
        string += chr(val & 0xFF)
        val >>= 8
    return string[::-1]

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
            self._hash_str = chord_hash(self._value)
            self._hash_int = pack_string(self._hash_str)

        elif isinstance(hashed, int):
            self._hash_str = unpack_string(hashed)
            self._hash_int = hashed

        elif isinstance(hashed, str):
            self._hash_str = hashed
            self._hash_int = pack_string(hashed)

        elif isinstance(hashed, Hash):  # copy
            self._hash_str = str(hashed)
            self._hash_int = int(hashed)
            self._value = hashed.value

        else:
            raise TypeError("Expected value or (int, str, Hash), got: "
                "value='%s',hashed='%s'" % (value, hashed))

        assert str(self) == unpack_string(int(self)), \
            "Unpacked hash must match direct hash!"

        assert len(str(self)) == (BITCOUNT / 8), \
            "Invalid hash size: %s" % str(self)

    @property
    def value(self):
        return self._value

    def __eq__(self, other):
        if isinstance(other, int):
            return int(self) == other
        elif isinstance(other, str):
            return str(self) == other
        elif isinstance(other, Hash):
            return int(self) == int(other)
        raise TypeError("Hash.__eq__ called with invalid parameter.")

    def __ne__(self, other):
        return not (self == other)

    def __str__(self):  return self._hash_str
    def __int__(self):  return self._hash_int % HASHMOD
    def __repr__(self): return str(int(self))


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
