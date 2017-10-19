#! /usr/bin/env python2
import os
import sys
sys.path.append('.')

import random
import unittest

from   cicada.chordlib.peersocket import *
from   cicada.chordlib.routing    import *
from   cicada.packetlib.message   import *


class TestPacketFunctions(unittest.TestCase):
    """ Tests various socket operations.
    """
    def test_readqueue(self):
        sender = Hash(value="sender")
        data = "some data."
        msg = MessageContainer(MessageType.MSG_CH_JOIN, sender, data=data)

        queue = ReadQueue()
        queue.read(msg.pack())

        self.assertTrue(queue.ready)
        pkt = queue.pop()

        self.assertEqual(pkt.data, data)
        self.assertEqual(msg.pack(), pkt.pack())

    def test_readqueue_responses(self):
        sender = Hash(value="sender")
        data = "some data."
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

    def test_readqueue_partial(self):
        sender = Hash(value="sender")
        send_data = "some partial %s suffix data." % "\x47\x4b\x04"
        msg = MessageContainer(MessageType.MSG_CH_JOIN, sender, data=send_data)

        data = msg.pack()
        part_1 = data[:len(data) / 2]
        part_2 = data[len(data) / 2:] + part_1
        part_3 = data[len(data) / 2:]

        queue = ReadQueue()
        queue.read(part_1)
        self.assertFalse(queue.ready)

        queue.read(part_2)
        self.assertTrue(queue.ready)

        pkt = queue.pop()
        self.assertEqual(pkt.data, send_data)
        self.assertEqual(data, pkt.pack())
        self.assertFalse(queue.ready)

        self.assertEqual(queue._pending, part_1)
        queue.read(part_3)
        self.assertTrue(queue.ready)

        pkt = queue.pop()
        self.assertEqual(pkt.data, send_data)
        self.assertEqual(data, pkt.pack())
        self.assertFalse(queue.ready)

    def test_readqueue_many(self):
        sender = Hash(value="sender")

        for _ in xrange(10):
            datas, queue = [], ReadQueue()

            # Add a random number of packets to the queue.
            queue_limit = random.randint(10, 25)
            for _ in xrange(queue_limit):
                data = os.urandom(random.randint(100, 1000))
                pkt = MessageContainer(random.choice([
                    MessageType.MSG_CH_JOIN,    MessageType.MSG_CH_INFO,
                    MessageType.MSG_CH_NOTIFY,  MessageType.MSG_CH_LOOKUP
                ]), sender, data=data)
                queue.read(pkt.pack())
                datas.append((pkt, data))

                self.assertTrue(queue.ready)

            for i in xrange(5):
                self.assertTrue(queue.ready)
                pkt = queue.pop()
                self.assertEqual(pkt.data, datas[i][1])
                self.assertEqual(pkt.pack(), datas[i][0].pack())


if __name__ == '__main__':
    unittest.main()
