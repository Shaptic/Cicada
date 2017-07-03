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

    def __init__(self, node_hash, listener_addr):
        if not isinstance(listener_addr, tuple) or len(listener_addr) != 2:
            raise TypeError("Please pass a two-tuple address!")

        super(JoinRequest, self).__init__(self.TYPE)

        self.node_hash = node_hash
        self.listener = listener_addr

    def pack(self):
        return struct.pack('!' + self.FORMAT,
            PackedHash(self.node_hash).pack(),
            PackedAddress(*self.listener).pack())

    @classmethod
    def unpack(cls, bytestream):
        nhash, bytestream = PackedHash.unpack(bytestream)
        addr, bytestream = PackedAddress.unpack(bytestream)

        assert not bytestream, \
            "Unpacked JR, but bytes remain: %s" % repr(bytestream)

        return cls(nhash, addr)

    def __str__(self):
        return "<%s | listen=%s:%d>" % (self.msg_type_str,
            self.listener[0], self.listener[1])


class JoinResponse(message.BaseMessage):
    """ Prepares a JOIN-RESP response packet.

    The response contains full metadata information about the node. This
    includes:
        - The hash length specifier, 2 bytes
        - The peer hash, based on the hash length.
        - Finger table:
            - finger table entry count, 4 bytes
            - the finger table entries, which is an interval, split into two
              4-byte integers outlining the range, as well as the hash and
              remote address of the peer responsible for that interval.
        - The peer listener socket, for other nodes to join.
    """

    TYPE = message.MessageType.MSG_CH_JOINR
    ENTRY_FORMAT = [
        "I",    # interval start
        "I",    # interval end
        PackedAddress.EMBED_FORMAT,
                # node address
        PackedHash.EMBED_FORMAT
                # hash
    ]

    RAW_FORMAT = [
        PackedHash.EMBED_FORMAT,    # hash of the sender
        PackedHash.EMBED_FORMAT,    # hash of the would-be successor
        PackedAddress.EMBED_FORMAT, # listener address of the would-be successor
        "I",    # number of entries in the table, usually BITCOUNT
        # a single table entry, repeated for the number of spec'd times
        "%ds"
    ]

    ENTRY = collections.namedtuple("Finger", "start end addr hash")
    FAKE_NODE = collections.namedtuple("Node", "local_addr hash")

    def __init__(self, sender_hash, succ_hash, listener_addr, finger_table=[]):
        """ Creates internal structures, including a fake finger table.

        :sender_hash    a Hash object for the node sending this message
        :succ_hash      a Hash object of the successor of the requestor
        :listener_addr  a 2-tuple address -- (IP, port) pair
        :finger_table   a list of `chordlib.fingertable.Finger`-like entries
        """
        super(JoinResponse, self).__init__(self.TYPE)

        if not isinstance(listener_addr, tuple) or len(listener_addr) != 2:
            raise TypeError("Please pass a two-tuple address!")

        if not isinstance(sender_hash, fingertable.Hash) or \
           not isinstance(succ_hash, fingertable.Hash):
            raise TypeError("Please provide a Hash object as the value.")

        self.sender_hash = sender_hash
        self.succ_hash = succ_hash
        self.listener = listener_addr

        self.fingers = []
        for entry in finger_table:
            self.fingers.append(self.ENTRY(entry.start, entry.end,
                entry.node.local_addr, entry.node.hash))

    def pack(self):
        entry_bytes = ''.join([
            struct.pack('!' + ''.join(self.ENTRY_FORMAT),
                entry.start, entry.end,
                PackedAddress(*entry.addr).pack(),
                PackedHash(entry.hash).pack()
            ) for entry in self.fingers
        ])

        pkt = struct.pack('!' + self.FORMAT % len(entry_bytes),
            PackedHash(self.sender_hash).pack(),
            PackedHash(self.succ_hash).pack(),
            PackedAddress(*self.listener).pack(),
            len(self.fingers), entry_bytes)

        return pkt

    @classmethod
    def unpack(cls, bytestream):
        send_hash, bytestream = PackedHash.unpack(bytestream)
        succ_hash, bytestream = PackedHash.unpack(bytestream)
        listener, bytestream  = PackedAddress.unpack(bytestream)
        finger_cnt, offset    = message.MessageContainer.extract_chunk(
            cls.RAW_FORMAT[3], bytestream, 0)

        get = lambda idx: message.MessageContainer.extract_chunk(
            cls.ENTRY_FORMAT[idx], bytestream, offset)

        fingers = []
        for i in xrange(finger_cnt):
            interval_st, offset  = get(0)
            interval_ed, offset  = get(1)
            addr, bytestream     = PackedAddress.unpack(bytestream)
            hash_val, bytestream = PackedHash.unpack(bytestream)

            node = cls.FAKE_NODE(addr, hash_val)
            fingers.append(fingertable.Finger(interval_st, interval_ed, node))

        return cls(send_hash, succ_hash, listener, fingers)

    def __str__(self):
        return "<%s | Node (%s:%d),hash=%s,fingers=%d>" % (
            self.msg_type_str, self.listener[0], self.listener[1],
            str(self.sender_hash)[:8], len(self.fingers))


class InfoRequest(message.BaseMessage):
    RAW_FORMAT = []
    TYPE = message.MessageType.MSG_CH_INFO

    def __init__(self):
        super(InfoRequest, self).__init__(self.TYPE)


class InfoResponse(JoinResponse):
    RAW_FORMAT = JoinResponse.RAW_FORMAT
    TYPE = message.MessageType.MSG_CH_INFOR

    def __init__(self, *args):
        super(InfoResponse, self).__init__(*args)


class NotifyRequest(message.BaseMessage):
    RAW_FORMAT = []
    TYPE = message.MessageType.MSG_CH_NOTIFY

    def __init__(self):
        super(NotifyRequest, self).__init__(self.TYPE)


class NotifyResponse(message.BaseMessage):
    RAW_FORMAT = [
        PackedHash.EMBED_FORMAT,        # sender hash

        PackedHash.EMBED_FORMAT,        # predecessor hash
        PackedAddress.EMBED_FORMAT,     # ^ address

        PackedHash.EMBED_FORMAT,        # successor hash
        PackedAddress.EMBED_FORMAT,     # ^ address
    ]
    TYPE = message.MessageType.MSG_CH_NOTIFYR

    def __init__(self, node_hash, succ, pred):
        """ Creates internal structures, including a fake finger table.

        :node_hash  a string representing the hash bytes
        :succ       successor node (inc. hash + listener address)
        :pred       predecessor node (inc. hash + listener address)
        """
        super(NotifyResponse, self).__init__(self.TYPE)

        if any([not isinstance(x, fingertable.Hash) for x in (
            node_hash, succ.hash, pred.hash)
        ]):
            raise TypeError("Please provide a Hash object.")

        self.node_hash = node_hash
        self.succ_hash = succ.hash
        self.pred_hash = pred.hash
        self.succ_addr = succ.local_addr
        self.pred_addr = pred.local_addr

    def pack(self):
        return struct.pack('!' + self.FORMAT,
            PackedHash(self.node_hash).pack(),

            PackedHash(self.pred_hash).pack(),
            PackedAddress(*self.pred_addr).pack(),

            PackedHash(self.succ_hash).pack(),
            PackedAddress(*self.succ_addr).pack())

    @classmethod
    def unpack(cls, bytestream):
        node_hash, bytestream = PackedHash(bytestream)
        pred_hash, bytestream = PackedHash(bytestream)
        pred_addr, bytestream = PackedAddress(bytestream)
        succ_hash, bytestream = PackedHash(bytestream)
        succ_addr, bytestream = PackedAddress(bytestream)

        FakeSocket = 0xFA#KE
        pn = remotenode.RemoteNode(pred_hash, pred_addr, pred_addr, FakeSocket)
        sn = remotenode.RemoteNode(succ_hash, succ_addr, succ_addr, FakeSocket)

        return cls(node_hash, pn, sn)


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

        self.node = sender_hash
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
