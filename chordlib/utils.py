import math


class FixedStack(object):
    """ Implements a fixed-sized list that pops off the oldest items.
    """

    def __init__(self, size):
        self.size = size
        self._list = []

    def append(self, item):
        self.list.append(item)
        while len(self) > self.size:
            self.list.pop(0)

    def remove(self, item):
        self.list.remove(item)

    def __len__(self):
        return len(self.list)

    @property
    def list(self):
        return self._list


def rad(deg):
    """ Converts a value to radians. """
    return (deg * math.pi) / 180.0

def in_range(a, x, y):
    """ Determines if a in [x, y). """
    return a >= x and a < y

def mxrange(start, end, step):
    """ Creates an iterator in [start, end) multiplying by step each time.
    """
    i = start
    while i < end:
        yield i
        i *= step

def find_last(string, char, start=0):
    """ Finds the index of the last instance of a substring.

    >>> tester = "stuff,again,more,things"
    >>> find_last(tester, ',')
    17
    >>> find_last(tester, 'f')
    4
    >>> find_last(tester, 'f', 8)
    -1
    """
    string = string[start:]
    index = -1
    while True:
        tmp = string.find("|", start)
        if tmp == -1: break
        start = index = tmp + 1

    return index

def nextmul(n, rd):
    """ Rounds a value `n` up to its nearest multiple of `rd`.

    >>> nextmul(7), nextmul(8), nextmul(9)
    (8, 8, 16)
    """
    return prevmul(n, rd) + rd

def prevmul(n, rd):
    """ Rounds a value `n` down to its nearest multiple of `rd`.
    """
    m = n % rd
    return n - m if m else n

def prevpow(n, e):
    """ Returns the next-lowest power of `e` of the value `n` (& the exponent).
    """
    lg = math.log(n, e)
    return e ** int(lg), lg
