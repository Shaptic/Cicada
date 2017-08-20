import enum
import time
import struct
import random
import collections

from chordlib  import routing
from chordlib  import chordnode
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
        "%dI" % int(routing.HASHLEN / 4),
                # hash value in discrete integers
    ]

    def __init__(self, hashval):
        if not isinstance(hashval, routing.Hash):
            raise TypeError("Can only serialize Hash objects.")

        self.hashval = hashval

    def pack(self):
        return struct.pack('!' + self.FORMAT, *self.hashval.parts)

    @classmethod
    def unpack(cls, bs):
        offset = 0
        get = lambda i: message.MessageContainer.extract_chunk(
            cls.RAW_FORMAT[i], bs, offset, keep_chunks=True)

        parts, i = get(0)
        return routing.Hash(hashed=routing.Hash.unpack_hash(parts)), bs[i:]


class PackedNode(PackedObject):
    """ Describes how to completely serialize a Chord node.
    """
    RAW_FORMAT = [
        PackedHash.EMBED_FORMAT,    # node hash
        PackedAddress.EMBED_FORMAT, # node listener
        "?",                        # predecessor valid bit
        PackedHash.EMBED_FORMAT,    # predecessor hash
        PackedAddress.EMBED_FORMAT, # predecessor listener
        "?",                        # successor valid bit
        PackedHash.EMBED_FORMAT,    # successor hash
        PackedAddress.EMBED_FORMAT  # successor listener
    ]

    def __init__(self, root, predecessor, successor):
        if not isinstance(root, chordnode.ChordNode):
            raise TypeError("expected ChordNode, got %s" % type(root))

        self.node = root
        self.predecessor = predecessor
        self.successor = successor

    def pack(self):
        pred_valid = self.predecessor is not None
        succ_valid = self.successor   is not None

        pred_hash = self.predecessor.hash if pred_valid else \
                    routing.Hash(hashed="0" * routing.HASHLEN)
        pred_addr = self.predecessor.chord_addr if pred_valid else \
                    ("0.0.0.0", 0)

        succ_hash = self.successor.hash if succ_valid else \
                    routing.Hash(hashed="0" * routing.HASHLEN)
        succ_addr = self.successor.chord_addr if succ_valid else \
                    ("0.0.0.0", 0)

        return struct.pack('!' + self.FORMAT,
                           PackedHash(self.node.hash).pack(),
                           PackedAddress(*self.node.chord_addr).pack(),
                           pred_valid,
                           PackedHash(pred_hash).pack(),
                           PackedAddress(*pred_addr).pack(),
                           succ_valid,
                           PackedHash(succ_hash).pack(),
                           PackedAddress(*succ_addr).pack())

    @classmethod
    def unpack(cls, bs):
        offset = 0
        get = lambda i: message.MessageContainer.extract_chunk(
            cls.RAW_FORMAT[i], bs, offset)

        node_hash, bs = PackedHash.unpack(bs)
        node_addr, bs = PackedAddress.unpack(bs)
        node = chordnode.ChordNode(node_hash, node_addr)

        offset = 0
        pred_valid, offset = get(2)
        pred_hash, bs = PackedHash.unpack(bs[offset:])
        pred_addr, bs = PackedAddress.unpack(bs)
        pred = chordnode.ChordNode(pred_hash, pred_addr) if pred_valid else None

        offset = 0
        succ_valid, offset = get(5)
        succ_hash, bs = PackedHash.unpack(bs[offset:])
        succ_addr, bs = PackedAddress.unpack(bs)
        succ = chordnode.ChordNode(succ_hash, succ_addr) if succ_valid else None

        node.predecessor = pred
        node.successor = succ
        return cls(node, pred, succ), bs


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
        :pred       the peer's predecessor node
        :succ       the peer's successor node
        """
        if any([not isinstance(x, chordnode.ChordNode) and x is not None \
                for x in (sender, pred, succ)]):
            raise TypeError("expected ChordNode's, got %s" % repr([
                            sender, pred, succ]))

        self.sender = sender
        self.predecessor = pred
        self.successor = succ

    def pack(self):
        return struct.pack('!' + self.FORMAT,
                           PackedNode(self.sender, self.predecessor,
                                      self.successor).pack())

    @classmethod
    def unpack(cls, bs):
        node, bs = PackedNode.unpack(bs)
        return cls(node.node, node.predecessor, node.successor)

    def __repr__(self):
        return "<INFOr | from=%d,pred=%d,succ=%d>" % (self.sender.hash,
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
        PackedHash.EMBED_FORMAT,    # joinee hash
        PackedAddress.EMBED_FORMAT  # joinee listener
    ]

    def __init__(self, sender_hash, listener_addr):
        if not isinstance(listener_addr, tuple) or len(listener_addr) != 2:
            raise TypeError("Please pass a two-tuple address!")

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

    def __repr__(self):
        return "<JOIN | from=%d,on=%s:%d>" % (self.sender, self.listener[0],
                                              self.listener[1])


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
        sub_info = sub_info[len("<INFO | ") : -1]
        return "<JOINr | result=%d@%s:%d | %s>" % (self.req_succ_hash,
            self.req_succ_addr[0], self.req_succ_addr[1], sub_info)


class NotifyRequest(InfoResponse):
    RAW_FORMAT = InfoResponse.RAW_FORMAT
    TYPE = message.MessageType.MSG_CH_NOTIFY
    RESPONSE = False

    def __init__(self, *args):
        super(NotifyRequest, self).__init__(*args)

    def __repr__(self):
        info_str = super(NotifyRequest, self).__repr__()
        return "<NOTIFY | %s>" % info_str[len("<INFO |") : -1]


class NotifyResponse(message.BaseMessage):
    RAW_FORMAT = [
        "?", # did we end up setting the sender as a new predecessor?
    ]
    TYPE = message.MessageType.MSG_CH_NOTIFY
    RESPONSE = True

    def __init__(self, set_predecessor):
        self.set_pred = set_predecessor

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
        PackedHash.EMBED_FORMAT,    # sender hash
        PackedHash.EMBED_FORMAT,    # hash to look up
    ]
    TYPE = message.MessageType.MSG_CH_LOOKUP

    def __init__(self, sender_hash, lookup_hash):
        if any([not isinstance(x, routing.Hash) for x in (
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
    TYPE = message.MessageType.MSG_CH_LOOKUP
    RESPONSE = True

    def __init__(self, sender_hash, lookup_hash, mapped_hash, mapped_address,
                 hops=1):
        if any([not isinstance(x, routing.Hash) for x in (
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
            PackedHash(self.sender).pack(),
            PackedHash(self.lookup).pack(),
            PackedHash(self.mapped).pack(),
            PackedAddress(*self.listener).pack(),
            self.hops)

    @classmethod
    def unpack(cls, bs):
        node,    bs = PackedHash.unpack(bs)
        lookup,  bs = PackedHash.unpack(bs)
        mapped,  bs = PackedHash.unpack(bs)
        address, bs = PackedAddress.unpack(bs)
        hops = message.MessageContainer.extract_chunk(cls.RAW_FORMAT[-1], bs, 0)

        return LookupResponse(node, lookup, mapped, address)


class StateMessage(message.BaseMessage):
    RAW_FORMAT = [
        PackedNode.EMBED_FORMAT,    # sender peer
        "H",                        # state variable
    ]
    TYPE = message.MessageType.MSG_CH_STATE

    def __init__(self, sender, state):
        self.sender = sender
        self.state = state.value if isinstance(state, enum.Enum) else int(state)

    def pack(self):
        return struct.pack('!' + self.FORMAT,
                           PackedNode(self.sender, self.sender.predecessor,
                                      self.sender.successor).pack(),
                           self.state)

    @classmethod
    def unpack(cls, bs):
        sender, bs = PackedNode.unpack(bs)
        state, bs = message.MessageContainer.extract_chunk(cls.RAW_FORMAT[-1],
                                                           bs, 0)
        return StateMessage(sender, state)


class PingMessage(message.BaseMessage):
    """ A heartbeat message pair that expects a matching value in the response.
    """
    RAW_FORMAT = [
        PackedHash.EMBED_FORMAT,
        "I",    # the pong message should have a matching 8-byte value
    ]
    TYPE = message.MessageType.MSG_CH_PING
    RESPONSE = False

    def __init__(self, sender, iv=None):
        self.sender = sender
        self.value = random.randint(1000, 2 ** 31) if not iv else iv

    def pack(self):
        return struct.pack('!' + self.FORMAT,
                           PackedHash(self.sender).pack(),
                           self.value)

    @classmethod
    def unpack(cls, bs):
        sender, bs = PackedHash.unpack(bs)
        v, _ = message.MessageContainer.extract_chunk(cls.RAW_FORMAT[1], bs, 0)
        return cls(sender, v)

    def __repr__(self):
        return "<%s | from=%d,val=%d>" % (message.MessageType.LOOKUP[self.TYPE],
                                          self.sender, self.value)


class PongMessage(PingMessage):
    """ A response to a PING message.
    """
    RAW_FORMAT = PingMessage.RAW_FORMAT
    TYPE = message.MessageType.MSG_CH_PONG
    RESPONSE = True

    def __init__(self, sender, ping_value):
        super(PongMessage, self).__init__(sender, iv=ping_value)
        self.time = time.time()


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
            except:
                print "Failed to .unpack() on type=%s, resp=%s" % (
                    msg.msg_type, msg.is_response)

    msg.dump()
    raise ValueError("the packet %s did not have an unpacker." % msg)
