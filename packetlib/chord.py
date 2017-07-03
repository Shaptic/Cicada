import struct
import collections

from chordlib  import fingertable
from chordlib  import remotenode
from packetlib import message
from packetlib import utils as pktutils


class PackedObject(object):
    __metaclass__ = message.FormatMetaclass
    RAW_FORMAT = []


class PackedAddress(PackedObject):
    """ Describes how to serialize an (IP address, port) pair.
    """
    RAW_FORMAT = [
        "I",    # 32-bit IPv4 address
        "H"     # 2-byte port
    ]

    def __init__(self, ip, port):
        self.address = (ip, port)

    def pack(self):
        return struct.pack('!' + self.FORMAT,
            pktutils.ip_to_int(self.address[0]),
            self.address[1])

    @classmethod
    def unpack(cls, bytestream):
        offset = 0
        get = lambda i: message.MessageContainer.extract_chunk(
            cls.RAW_FORMAT[i], bytestream, offset)

        ip,     offset = get(0)
        port,   offset = get(1)
        return (pktutils.int_to_ip(ip), port), bytestream[offset:]


class PackedHash(PackedObject):
    """ Describes how to serialize a `Hash` object.
    """
    RAW_FORMAT = [
        "H",    # hash length, in bytes (32 for SHA256)
        "%ds" % (fingertable.BITCOUNT / 8),
                # SHA256 hash
    ]

    def __init__(self, hashval):
        if not isinstance(hashval, fingertable.Hash):
            raise TypeError("Can only serialize Hash objects.")

        self.hashval = hashval

    def pack(self):
        return struct.pack('!' + self.FORMAT,
            len(str(self.hashval)),
            str(self.hashval))

    @classmethod
    def unpack(cls, bytestream):
        offset = 0
        get = lambda i: message.MessageContainer.extract_chunk(
            cls.RAW_FORMAT[i], bytestream, offset)

        hashlen, offset = get(0)
        nhash,   offset = get(1)

        return fingertable.Hash(hashed=nhash), bytestream[offset:]


class InfoRequest(message.BaseMessage):
    RAW_FORMAT = []
    TYPE = message.MessageType.MSG_CH_INFO

    def __init__(self):
        super(InfoRequest, self).__init__(self.TYPE)


class InfoResponse(message.BaseMessage):
    RAW_FORMAT = [
        PackedHash.EMBED_FORMAT,        # sender hash

        PackedHash.EMBED_FORMAT,        # sender's predecessor hash
        PackedAddress.EMBED_FORMAT,     # ^ address

        PackedHash.EMBED_FORMAT,        # sender's successor hash
        PackedAddress.EMBED_FORMAT,     # ^ address
    ]
    TYPE = message.MessageType.MSG_CH_INFOR

    def __init__(self, sender, pred, succ):
        """ Creates internal structures for the INFO message.

        :sender     a `Hash` of the peer sending this message
        :succ       successor node (inc. hash + listener address)
        :pred       predecessor node (inc. hash + listener address)
        """
        super(InfoResponse, self).__init__(self.TYPE)

        if any([not isinstance(x, fingertable.Hash) for x in (
            sender, succ.hash, pred.hash)
        ]):
            raise TypeError("Please provide a Hash object.")

        self.successor = succ
        self.predecessor = pred

        self.sender = sender
        self.succ_hash = succ.hash
        self.pred_hash = pred.hash
        self.succ_addr = succ.local_addr
        self.pred_addr = pred.local_addr

    def pack(self):
        return struct.pack('!' + self.FORMAT,
            PackedHash(self.sender).pack(),
            PackedHash(self.pred_hash).pack(),
            PackedAddress(*self.pred_addr).pack(),
            PackedHash(self.succ_hash).pack(),
            PackedAddress(*self.succ_addr).pack())

    @classmethod
    def unpack(cls, bytestream):
        send_hash, bytestream = PackedHash.unpack(bytestream)
        pred_hash, bytestream = PackedHash.unpack(bytestream)
        pred_addr, bytestream = PackedAddress.unpack(bytestream)
        succ_hash, bytestream = PackedHash.unpack(bytestream)
        succ_addr, bytestream = PackedAddress.unpack(bytestream)

        FakeSocket = 0xFA#KE
        pn = remotenode.RemoteNode(pred_hash, pred_addr, pred_addr, FakeSocket)
        sn = remotenode.RemoteNode(succ_hash, succ_addr, succ_addr, FakeSocket)

        return cls(send_hash, pn, sn)


class JoinRequest(message.BaseMessage):
    """ Prepares a JOIN request.

    A JOIN packet will include the listener address of the local Chord node that
    is sending out this message. This way, other peers can route through to this
    node.
    """

    TYPE = message.MessageType.MSG_CH_JOIN
    RAW_FORMAT = [
        PackedHash.EMBED_FORMAT,
        PackedAddress.EMBED_FORMAT
    ]

    def __init__(self, sender_hash, listener_addr):
        if not isinstance(listener_addr, tuple) or len(listener_addr) != 2:
            raise TypeError("Please pass a two-tuple address!")

        super(JoinRequest, self).__init__(self.TYPE)

        self.sender = sender_hash
        self.listener = listener_addr

    def pack(self):
        return struct.pack('!' + self.FORMAT,
            PackedHash(self.sender).pack(),
            PackedAddress(*self.listener).pack())

    @classmethod
    def unpack(cls, bytestream):
        shash, bytestream = PackedHash.unpack(bytestream)
        addr, bytestream = PackedAddress.unpack(bytestream)

        assert not bytestream, \
            "Unpacked JR, but bytes remain: %s" % repr(bytestream)

        return cls(shash, addr)


class JoinResponse(InfoResponse):
    RAW_FORMAT = [
        InfoResponse.EMBED_FORMAT,
        PackedHash.EMBED_FORMAT,        # requestor's successor hash
        PackedAddress.EMBED_FORMAT,     # ^ address
    ]
    TYPE = message.MessageType.MSG_CH_JOINR

    def __init__(self, req_succ, *args):
        """ Prepares a respones to a JOIN request.

        :req_succ   a node corresponding to a successor of the JOIN sender
        :args       the remaining parameters are sent directly to InfoResponse
        """
        super(JoinResponse, self).__init__(*args)
        self.request_successor = req_succ
        self.req_succ_hash = req_succ.hash
        self.req_succ_addr = req_succ.local_addr

    def pack(self):
        old_fmt = self.FORMAT
        self.FORMAT = InfoResponse.FORMAT
        embedded  = super(JoinResponse, self).pack()
        self.FORMAT = old_fmt

        return struct.pack('!' + self.FORMAT,
            embedded,
            PackedHash(self.request_successor.hash).pack(),
            PackedAddress(*self.request_successor.local_addr).pack())

    @classmethod
    def unpack(cls, bytestream):
        info = InfoResponse.unpack(bytestream)

        bytestream = bytestream[len(info.pack()):]  # inefficient but idc tbh
        req_succ_hash, bytestream = PackedHash.unpack(bytestream)
        req_succ_addr, bytestream = PackedAddress.unpack(bytestream)

        FakeSocket = 0xFA#KE
        rsn = remotenode.RemoteNode(req_succ_hash,
            req_succ_addr, req_succ_addr, FakeSocket)

        return cls(rsn, info.sender, info.predecessor, info.successor)


class NotifyRequest(message.BaseMessage):
    RAW_FORMAT = []
    TYPE = message.MessageType.MSG_CH_NOTIFY

    def __init__(self):
        super(NotifyRequest, self).__init__(self.TYPE)


class NotifyResponse(JoinResponse):
    RAW_FORMAT = JoinResponse.RAW_FORMAT
    TYPE = message.MessageType.MSG_CH_NOTIFYR

    def __init__(self, *args):
        super(NotifyResponse, self).__init__(self.TYPE)


class LookupRequest(message.BaseMessage):
    RAW_FORMAT = [
        PackedHash.EMBED_FORMAT,    # sender hash
        PackedHash.EMBED_FORMAT,    # hash to look up
    ]
    TYPE = message.MessageType.MSG_CH_LOOKUP

    def __init__(self, sender_hash, lookup_hash):
        if any([not isinstance(x, fingertable.Hash) for x in (
            sender_hash, lookup_hash)
        ]):
            raise TypeError("Please provide a Hash object.")

        self.sender = sender_hash
        self.lookup = lookup_hash

    def pack(self):
        return struct.pack('!' + self.FORMAT,
            PackedHash(self.sender).pack(),
            PackedHash(self.lookup).pack())

    @classmethod
    def unpack(cls, bs):
        sender, bs = PackedHash.unpack(bs)
        lookup, bs = PackedHash.unpack(bs)

        assert bs == "", "Remaining bytes?? %s" % bs
        return LookupRequest(sender, lookup)


class LookupResponse(message.BaseMessage):
    RAW_FORMAT = [
        PackedHash.EMBED_FORMAT,    # sender hash
        PackedHash.EMBED_FORMAT,    # lookup hash
        PackedHash.EMBED_FORMAT,    # resulting mapped node hash
        PackedAddress.EMBED_FORMAT, # resulting mapped node listener
        "H",    # number of hops it took
    ]
    TYPE = message.MessageType.MSG_CH_LOOKUPR

    def __init__(self, sender_hash, lookup_hash, mapped_hash, mapped_address,
                 hops=1):
        if any([not isinstance(x, fingertable.Hash) for x in (
            sender_hash, lookup_hash, mapped_hash)
        ]):
            raise TypeError("Please provide a Hash object.")

        self.sender = sender_hash
        self.lookup = lookup_hash
        self.mapped = mapped_hash
        self.listener = mapped_address
        self.hops = hops

    def pack(self):
        return struct.pack('!' + self.FORMAT,
            PackedHash(self.node).pack(),
            PackedHash(self.lookup).pack(),
            PackedHash(self.mapped).pack(),
            PackedAddress(*self.listener).pack(),
            self.hops)

    @classmethod
    def unpack(self, bs):
        node,    bs = PackedHash.unpack(bs)
        lookup,  bs = PackedHash.unpack(bs)
        mapped,  bs = PackedHash.unpack(bs)
        address, bs = PackedAddress.unpack(bs)
        hops = message.MessageContainer.extract_chunk(self.RAW_FORMAT[-1], bs, 0)

        return LookupResponse(node, lookup, mapped, address)
