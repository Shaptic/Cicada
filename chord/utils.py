import math

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

def listify(fn):
    """ Turns a method that takes a single argument into one that takes lists.
    """
    def wrapper(self, single_arg, *args, **kwargs):
        if isinstance(single_arg, (list, tuple)):
            for item in single_arg:
                fn(self, item, *args, **kwargs)
        else:
            return fn(self, single_arg, *args, **kwargs)
    return wrapper

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

def nextmul(n, rd=8):
    """ Rounds a value up to its nearest multiple of 8. power of two.

    >>> next_po2(7), next_po2(8), next_po2(9)
    (8, 8, 16)
    """
    m = n % rd
    return n - m + rd if m else n
