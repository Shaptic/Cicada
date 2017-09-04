import threading
import time
import math

class InfiniteThread(threading.Thread):
    """ An abstract thread to run a method forever until its stopped.
    """
    def __init__(self, pause=0, **kwargs):
        super(InfiniteThread, self).__init__(**kwargs)
        self._sleep = pause
        self.running = True
        self.setDaemon(True)

    def run(self):
        while self.running:
            self._loop_method()
            time.sleep(self.sleep)

    def _loop_method(self):
        raise NotImplemented

    def stop_running(self):
        self.running = False

    @property
    def sleep(self):
        return self._sleep() if callable(self._sleep) else self._sleep


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


class LockedSet(object):
    """ Implements a set that locks when iterating.
    """
    def __init__(self):
        self.set = set()
        self.setlock = threading.RLock()

    def add(self, item):
        with self.setlock:
            self.set.add(item)

    def remove(self, item):
        with self.setlock:
            self.set.remove(item)

    def difference(self, other):
        with self.setlock:
            return self.set.difference(other)

    def __iter__(self):
        with self.setlock:
            for item in self.set:
                yield item

    def lockfree_iter(self):
        for item in self.set:
            yield item

    def __len__(self):
        with self.setlock:
            return len(self.set)


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

    >>> nextmul(7, 8), nextmul(8, 8), nextmul(9, 8)
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
