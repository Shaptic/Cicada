#! /usr/bin/env python2
import sys
import time
import unittest
sys.path.append(".")

from cicada import swarmlib


class TestSwarmPeer(unittest.TestCase):
    def test_swarmpeer(self):
        a, b = swarmlib.SwarmPeer(), swarmlib.SwarmPeer()
        a.bind("localhost", 0xC1CADA & 0xFF00)
        b.bind("localhost", 0xC1CADA & 0xFFFE)

        b.connect(*a.listener)
        a.send(b, "ECHO ME")
        _, d, _ = b.recv()
        b.send(a, d[::-1])
        a.recv()

if __name__ == '__main__':
    unittest.main()
