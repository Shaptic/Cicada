""" A stripped-down implementation of the Chord protocol.
"""

import sys
import logging

class ChordFormatter(logging.Formatter):
    """ Allows for special formatting for debug logging to include line info.
    """

    PREFIX = "[%s | %%(asctime)s]"
    SUFFIX = "%(levelname)08s: %(message)s"
    FORMAT = "%s %s" % (PREFIX % ("%(module)s"), SUFFIX)
    FORMAT = DEBUG_FORMAT = "%s %s" % (
        "",#"[%(asctime)s]",
        # PREFIX % "%(module)s:%(filename)s:%(funcName)s:%(lineno)s",
        SUFFIX)
    ERROR_FORMAT = "%(module)s:%(filename)s:%(funcName)s:%(lineno)s " + FORMAT

    def __init__(self):
        super(ChordFormatter, self).__init__(fmt=self.FORMAT,
            datefmt="%H:%M:%S")

    def format(self, record):
        orig = self._fmt

        if record.levelno == logging.DEBUG:
            self._fmt = self.DEBUG_FORMAT

        elif record.levelno in (logging.ERROR, logging.CRITICAL):
            self._fmt = self.ERROR_FORMAT

        result = super(ChordFormatter, self).format(record)

        self._fmt = orig
        return result

h = logging.StreamHandler(sys.stdout)
h.setFormatter(ChordFormatter())

L = log = logging.getLogger(__name__)
L.addHandler(h)
L.setLevel(logging.DEBUG)
