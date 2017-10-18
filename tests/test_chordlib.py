import os
import random
import string
import unittest
import sys
sys.path.append(".")

from cicada.packetlib import debug
from cicada.packetlib import chord
from cicada.packetlib import message
from cicada.chordlib  import routing
from cicada.chordlib  import chordnode


class TestHashing(unittest.TestCase):
    """ Tests that packing and unpacking hashes works.
    """
    HASH_COUNT = 1000

    def test_hashes(self):
        for i in xrange(self.HASH_COUNT):
            start = ''.join([
                random.choice(string.lowercase) for _ in xrange(
                    random.randint(10, 20)
                )
            ])

            # print "Hashing value: %s" % repr(start)
            h = routing.Hash(value=start)
            self.assertEqual(routing.Hash.pack_hash(str(h)), h.parts)


class TestMessagePacking(unittest.TestCase):
    """ Tests that the `.pack()` and `.unpack()` methods of each message works.
    """
    def test_messagecontainer(self):
        h = routing.Hash(value="sender")
        n = message.MessageContainer(message.MessageType.MSG_CH_NOTIFY, h,
                                     data="hey babes\x77hey", sequence=2884)
        # debug.dump_packet(n.pack(), n.full_format())
        self.assertEqual(n.pack(), self._repack(n.pack()))

    def test_inforequest(self):
        sender = routing.Hash(value="sender")
        pkt = chord.InfoRequest.make_packet(sender)
        # debug.dump_packet(pkt.pack(), pkt.full_format())
        self.assertEqual(pkt.pack(), self._repack(pkt.pack()))

    def test_inforesponse(self):
        sender = routing.Hash(value="sender")
        send_node = chordnode.ChordNode(sender, ("localhost", 0xB00B))

        req = chord.InfoRequest.make_packet(sender)
        req.pack()     # need to pack for checksum injection
        pkt = chord.InfoResponse.make_packet(sender, send_node, None, None,
                                             original=req)
        self.assertEqual(pkt.pack(), self._repack(pkt.pack()))

    def test_inforesponse_with_predecessor(self):
        sender = routing.Hash(value="sender")
        send_node = chordnode.ChordNode(sender, ("localhost", 0xB00B))

        req = chord.InfoRequest.make_packet(sender)
        req.pack()     # need to pack for checksum injection
        pkt = chord.InfoResponse.make_packet(sender, send_node, send_node,
                                             send_node, original=req)
        self.assertEqual(pkt.pack(), self._repack(pkt.pack()))

    def test_inforesponse_with_successor(self):
        sender = routing.Hash(value="sender")
        send_node = chordnode.ChordNode(sender, ("localhost", 0xB00B))

        req = chord.InfoRequest.make_packet(sender)
        req.pack()     # need to pack for checksum injection
        pkt = chord.InfoResponse.make_packet(sender, send_node, None, send_node,
                                             original=req)
        self.assertEqual(pkt.pack(), self._repack(pkt.pack()))

    def test_joinrequest(self):
        sender = routing.Hash(value="sender")
        pkt = chord.JoinRequest.make_packet(sender, ("127.0.0.1", 0xB00B))
        self.assertEqual(pkt.pack(), self._repack(pkt.pack()))

    def test_joinresponse(self):
        sender = routing.Hash(value="sender")
        send_node = chordnode.ChordNode(sender, ("localhost", 0xB00B))

        req = chord.JoinRequest.make_packet(sender, ("127.0.0.1", 0xB00B))
        req.pack()     # need to pack for checksum injection
        pkt = chord.JoinResponse.make_packet(sender, send_node, send_node, None,
                                             None, original=req)
        self.assertEqual(pkt.pack(), self._repack(pkt.pack()))

    def test_notifyrequest(self):
        self.test_inforequest()

    def test_notifyresponse_yes(self):
        self._notify_response(True)

    def test_notifyresponse_no(self):
        self._notify_response(False)

    def _notify_response(self, flag):
        sender = routing.Hash(value="sender")
        send_node = chordnode.ChordNode(sender, ("localhost", 0xB00B))

        req = chord.NotifyRequest.make_packet(sender, send_node, send_node,
                                              send_node); req.pack()

        pkt = chord.NotifyResponse.make_packet(sender, flag, original=req)
        self.assertEqual(pkt.pack(), self._repack(pkt.pack()))

    def test_lookuprequest(self):
        sender = routing.Hash(value="sender")
        lookup = routing.Hash(value="lookup")
        pkt = chord.LookupRequest.make_packet(sender, lookup)
        self.assertEqual(pkt.pack(), self._repack(pkt.pack()))

    def test_lookuprequest_with_data(self):
        sender = routing.Hash(value="sender")
        lookup = routing.Hash(value="lookup")

        for _ in xrange(100):
            data = os.urandom(random.randint(100, 10000))
            pkt = chord.LookupRequest.make_packet(sender, lookup, data)
            self.assertEqual(pkt.pack(), self._repack(pkt.pack()))

    def test_lookupresponse(self):
        sender = routing.Hash(value="sender")
        lookup = routing.Hash(value="lookup")

        req = chord.LookupRequest.make_packet(sender, lookup); req.pack()
        pkt = chord.LookupResponse.make_packet(sender, lookup, sender,
                                               ("127.0.0.1", 0xB00B), 5,
                                               original=req)
        self.assertEqual(pkt.pack(), self._repack(pkt.pack()))

    def _repack(self, bs):
        return message.MessageContainer.unpack(bs).pack()


if __name__ == '__main__':
    unittest.main()
