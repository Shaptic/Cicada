#!/usr/bin/env python2
""" Defines various packet structures for the Chord DHT protocol.
"""

import enum
import time
import struct
import random
import collections

from ..chordlib  import routing
from ..chordlib  import chordnode
from ..packetlib import message
from ..packetlib import utils as pktutils

from ..packetlib.message import PackedHash, PackedAddress, PackedNode


class InfoRequest(message.BaseMessage):
    RAW_FORMAT = []
    TYPE = message.MessageType.MSG_CH_INFO
    @classmethod
    def unpack(cls, bs): return InfoRequest()
    def __repr__(self): return "<INFO>"


class InfoResponse(message.BaseMessage):
    RAW_FORMAT = [ PackedNode.EMBED_FORMAT ]
    TYPE = message.MessageType.MSG_CH_INFO
    RESPONSE = True

    def __init__(self, sender, pred, succ):
        """ Creates internal structures for the INFO message.

        :sender     a `ChordNode` instance of the peer sending their info
        :pred       the peer's predecessor node (or `None`)
        :succ       the peer's successor node (or `None`)
        """
        if any([not isinstance(x, chordnode.ChordNode) and x is not None \
                for x in (sender, pred, succ)]):
            raise TypeError("expected ChordNode's, got %s" % repr([
                            sender, pred, succ]))

        self.sender = sender
        self.predecessor = pred
        self.successor = succ
        self.time = time.time()

    def pack(self):
        return struct.pack('!' + self.FORMAT,
                           PackedNode(self.sender, self.predecessor,
                                      self.successor).pack())

    @classmethod
    def unpack(cls, bs):
        node, bs = PackedNode.unpack(bs)
        return cls(node.node, node.predecessor, node.successor)

    def __repr__(self):
        return "<INFOr | hash=%d,pred=%d,succ=%d>" % (self.sender.hash,
            0 if not self.predecessor else self.predecessor.hash,
            0 if not self.successor   else self.successor.hash)


class JoinRequest(message.BaseMessage):
    """ Prepares a JOIN request.

    A JOIN packet will include the listener address of the local Chord node that
    is sending out this message. This way, other peers can route through to this
    node.
    """
    TYPE = message.MessageType.MSG_CH_JOIN
    RAW_FORMAT = [
        PackedAddress.EMBED_FORMAT  # joinee listener
    ]

    def __init__(self, listener_addr):
        if not isinstance(listener_addr, tuple) or len(listener_addr) != 2:
            raise TypeError("Please pass a two-tuple address!")

        self.listener = listener_addr

    def pack(self):
        return struct.pack('!' + self.FORMAT,
                           PackedAddress(*self.listener).pack())

    @classmethod
    def unpack(cls, bytestream):
        addr, bs = PackedAddress.unpack(bytestream)
        assert not bs, "Unpacked JR, but bytes remain: %s" % repr(bs)
        return cls(addr)

    def __repr__(self):
        return "<JOIN | on=%s:%d>" % self.listener


class JoinResponse(InfoResponse):
    RAW_FORMAT = [
        InfoResponse.EMBED_FORMAT,
        PackedHash.EMBED_FORMAT,        # requestor's successor hash
        PackedAddress.EMBED_FORMAT,     # ^ address
    ]
    TYPE = message.MessageType.MSG_CH_JOIN
    RESPONSE = True

    def __init__(self, req_succ, *args):
        """ Prepares a respones to a JOIN request.

        :req_succ   a node corresponding to a successor of the JOIN sender
        :args       the remaining parameters are sent directly to `InfoResponse`
        """
        super(JoinResponse, self).__init__(*args)
        self.request_successor = req_succ
        self.req_succ_hash = req_succ.hash
        self.req_succ_addr = req_succ.chord_addr

    def pack(self):
        old_fmt = self.FORMAT
        self.FORMAT = InfoResponse.FORMAT
        embedded  = super(JoinResponse, self).pack()
        self.FORMAT = old_fmt

        return struct.pack('!' + self.FORMAT, embedded,
                           PackedHash(self.req_succ_hash).pack(),
                           PackedAddress(*self.req_succ_addr).pack())

    @classmethod
    def unpack(cls, bytestream):
        info = InfoResponse.unpack(bytestream)

        bytestream = bytestream[len(info.pack()):]  # inefficient but idc tbh
        req_succ_hash, bytestream = PackedHash.unpack(bytestream)
        req_succ_addr, bytestream = PackedAddress.unpack(bytestream)

        rsn = chordnode.ChordNode(routing.Hash(hashed=req_succ_hash),
                                  req_succ_addr)

        return cls(rsn, info.sender, info.predecessor, info.successor)

    def __repr__(self):
        sub_info = super(JoinResponse, self).__repr__()
        return "<JOINr | result=%d@%s:%d | %s>" % (
               self.req_succ_hash, self.req_succ_addr[0], self.req_succ_addr[1],
               sub_info[len("<INFO | ") : -1])


class NotifyRequest(InfoResponse):
    RAW_FORMAT = InfoResponse.RAW_FORMAT
    TYPE = message.MessageType.MSG_CH_NOTIFY
    RESPONSE = False

    def __init__(self, *args):
        super(NotifyRequest, self).__init__(*args)

    def __repr__(self):
        info_str = super(NotifyRequest, self).__repr__()
        return "<NOTIFY | %s>" % info_str[len("<INFO | ") : -1]


class NotifyResponse(message.BaseMessage):
    RAW_FORMAT = [
        "?", # did we end up setting the sender as a new predecessor?
    ]
    TYPE = message.MessageType.MSG_CH_NOTIFY
    RESPONSE = True

    def __init__(self, pred_is_set):
        self.set_pred = pred_is_set

    def pack(self):
        return struct.pack('!' + self.FORMAT, self.set_pred)

    @classmethod
    def unpack(cls, bs):
        bit = struct.unpack('!' + cls.FORMAT, bs)
        return cls(bit)

    def __repr__(self):
        return "<NOTIFYr | set=%s>" % bool(self.set_pred)


class LookupRequest(message.BaseMessage):
    RAW_FORMAT = [
        PackedHash.EMBED_FORMAT,    # hash to look up
        "I",                        # length of data to send, if any
        "%ds",                      # additional data, if any
    ]
    TYPE = message.MessageType.MSG_CH_LOOKUP

    def __init__(self, lookup_hash, data=""):
        if not isinstance(lookup_hash, routing.Hash):
            raise TypeError("Please provide a Hash object.")

        self.lookup = lookup_hash
        self.data = data

    def pack(self):
        return struct.pack('!' + self.FORMAT % len(self.data),
                           PackedHash(self.lookup).pack(),
                           len(self.data), self.data)

    @classmethod
    def unpack(cls, bs):
        get = lambda f: message.MessageContainer.extract_chunk(f, bs, offset)

        offset = 0
        lookup, bs     = PackedHash.unpack(bs)
        dlen,   offset = get(cls.RAW_FORMAT[1])
        data,   offset = get(cls.RAW_FORMAT[2] % dlen)

        assert bs[offset:] == "", "Remaining bytes?? %s" % bs[offset:]
        return LookupRequest(lookup, data)

    def __repr__(self):
        return "<LOOKUP | value=%d>" % (self.lookup)


class LookupResponse(message.BaseMessage):
    RAW_FORMAT = [
        PackedHash.EMBED_FORMAT,    # lookup hash
        PackedHash.EMBED_FORMAT,    # resulting mapped node hash
        PackedAddress.EMBED_FORMAT, # resulting mapped node listener
        "H",    # number of hops it took
    ]
    TYPE = message.MessageType.MSG_CH_LOOKUP
    RESPONSE = True

    def __init__(self, lookup_hash, mapped_hash, mapped_address, hops=1):
        if any([not isinstance(x, routing.Hash) for x in (
            lookup_hash, mapped_hash)
        ]):
            raise TypeError("Please provide a Hash object.")

        self.lookup = lookup_hash
        self.mapped = mapped_hash
        self.listener = mapped_address
        self.hops = hops

    def pack(self):
        return struct.pack('!' + self.FORMAT,
            PackedHash(self.lookup).pack(),
            PackedHash(self.mapped).pack(),
            PackedAddress(*self.listener).pack(),
            self.hops)

    @classmethod
    def unpack(cls, bs):
        lookup,  bs = PackedHash.unpack(bs)
        mapped,  bs = PackedHash.unpack(bs)
        address, bs = PackedAddress.unpack(bs)
        hops = message.MessageContainer.extract_chunk(cls.RAW_FORMAT[-1], bs, 0)

        return LookupResponse(lookup, mapped, address, hops[0])

    def __repr__(self):
        return "<LOOKUPr %d | result=%d,%s:%d,hops=%d>" % (
               self.sender, self.mapped, self.listener[0],
               self.listener[1], self.hops)


def generic_unpacker(msg):
    for packet_type in (
        JoinRequest,    JoinResponse,
        InfoRequest,    InfoResponse,
        NotifyRequest,  NotifyResponse,
        LookupRequest,  LookupResponse,
        PingMessage,    PongMessage
    ):
        if msg.type == packet_type.TYPE and \
           msg.is_response == packet_type.RESPONSE:
            try:
                return packet_type.unpack(msg.data)
            except Exception, e:
                print "Failed to .unpack() on type=%s, resp=%s" % (
                    msg.msg_type, msg.is_response)
                print str(e)

    msg.dump()
    raise ValueError("the packet %s did not have an unpacker." % msg)
