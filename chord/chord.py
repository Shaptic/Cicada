#!/usr/bin/env python2
""" A stripped-down implementation of the Chord protocol.
"""

import sys
import time
import math
import random
import string
import threading

import hashring
import localnode
import remotenode
from utils   import *

if __name__ == "__main__" and __package__ is None:
    __package__ = "cicada.chord"

def walk_ring(root, maxcount=10):
    count = 0
    firstOne = root
    nextOne = firstOne.successor

    yield firstOne
    while nextOne is not None and \
          root != nextOne and \
          count < maxcount:   # so we don't do it too much if there's an error
        yield nextOne
        nextOne = nextOne.successor
        count += 1

def print_ring(root):
    for node in walk_ring(root):
        print node

def main():
    address_ring = [
        ("192.168.0.1", 2016 + i) for i in xrange(10)
    ]

    nodes = sorted([
        localnode.LocalChordNode("%s:%d" % _) for _ in address_ring
    ], key=lambda x: x.hash)

    return nodes
