""" Provides helpful packet-oriented utilities.
"""
import threading


def ip_to_int(addr):
    """ Converts a 4-octet IPv4 address string into an integer.
    """
    a, b, c, d = addr.split('.')
    return sum([
        int(a) << 24,
        int(b) << 16,
        int(c) << 8,
        int(d)
    ])


def int_to_ip(n):
    """ Converts a 32-bit integer into a 4-octet IPv4 address string.
    """
    return '.'.join([
        str((n & (0xFF << s)) >> s) for s in xrange(24, -1, -8)
    ])


class ConditionQueue(object):
    """ A one-to-one condition-based FIFO queue.

    This lets you synchronize a producer (adding to the queue) with a consumer
    (popping off the queue).

    The producer adds data to the queue as they normally would (`push()`).
    The consumer waits for content as follows:

    ```python

        # assume the `ConditionQueue` instance is `queue`
        with queue:
            queue.wait()

            # doesn't necessarily need to occur inside of the `with` statement
            # if there's only one consumer
            data = queue.pop()

        # use `data`
    ```

    NOTE: If the above paradigm isn't followed, the consumer may block the
          producer flow.
    """
    def __init__(self):
        self._queue = []
        self._queue_lock = threading.RLock()
        self._queue_cond = threading.Condition(self._queue_lock)

    def push(self, item):
        with self._queue_lock:
            self._queue.append(item)
            self._queue_cond.notify()

    def pop(self):
        """ Removes the oldest packet from the queue. """
        with self._queue_lock:
            return self._queue.pop(0)

    def wait(self):
        while not self.ready:
            self._queue_cond.wait()

    def __enter__(self):
        self._queue_cond.acquire()

    def __exit__(self, exc_type, exc_value, traceback):
        self._queue_cond.release()
        # return True    # suppress exceptions

    def __len__(self):
        return len(self.queue)

    @property
    def ready(self):
        return bool(self._queue)
