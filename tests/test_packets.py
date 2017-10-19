#! /usr/bin/env python2
import sys
sys.path.append('.')

import unittest

from   cicada.chordlib.peersocket import *
from   cicada.chordlib.routing    import *
from   cicada.packetlib.message   import *


class TestPacketFunctions(unittest.TestCase):
    """ Tests various socket operations.
    """
    def test_readqueue(self):
        sender = Hash(value="sender")
        data = "some data %s using ending." % MessageContainer.END
        msg = MessageContainer(MessageType.MSG_CH_JOIN, sender, data=data)

        queue = ReadQueue()
        queue.read(msg.pack())

        self.assertTrue(queue.ready)
        pkt = queue.pop()

        self.assertEqual(pkt.data, data)
        self.assertEqual(msg.pack(), pkt.pack())

    def test_readqueue_responses(self):
        sender = Hash(value="sender")
        data = "some data %s using ending." % MessageContainer.END
        orig = MessageContainer(MessageType.MSG_CH_JOIN, sender, data=data)
        orig.pack()
        msg = MessageContainer(MessageType.MSG_CH_JOIN, sender, data=data,
                               original=orig)

        queue = ReadQueue()
        queue.read(msg.pack())

        self.assertTrue(queue.ready)
        pkt = queue.pop()

        self.assertEqual(pkt.data, data)
        self.assertEqual(msg.pack(), pkt.pack())


if __name__ == '__main__':
    unittest.main()
