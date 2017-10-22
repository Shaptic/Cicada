#!/usr/bin/env python2
""" Defines various packet structures for the higher-level Ciacada protocol.
"""
import enum
import struct

from .           import message
from ..chordlib  import routing


class MessageType(enum.IntEnum):
    """ Describes the various types of messages in the Cicada protocol.
    """
    MSG_CI_DATA     = 0xFF00
    MSG_CI_BCAST    = 0xFF01

# A simple constant-to-string conversion table for human-readability.
MessageLookup = {
    MessageType.MSG_CI_DATA:    "DATA",
    MessageType.MSG_CI_BCAST:   "BCAST",
}


class CicadaBaseMessage(object):
    """ The base class for all Cicada messages.
    """
    __metaclass__ = message.FormatMetaclass
    RAW_FORMAT = ["H"]

    def pack(self):
        return struct.pack("!" + ''.join(CicadaBaseMessage.RAW_FORMAT),
                           int(self.type))

    @classmethod
    def make_packet(cls, *args, **kwargs):
        pkt = cls(*args, **kwargs)
        pkt.type = cls.CI_TYPE
        return pkt

    @staticmethod
    def unpack(bs):
        fmt = ''.join(CicadaBaseMessage.FORMAT)
        return bs[struct.calcsize(fmt):]

    @property
    def msg_type(self):
        return MessageLookup[self.type]


class BroadcastMessage(CicadaBaseMessage):
    """ A raw data packet to broadcast on the network.

    The broadcasting algorithm tries to avoid unnecessary packet duplication by
    maintaining a fixed-size queue of hashes of visited nodes. A peer that sees
    a broadcast packet will rebroadcast it to everyone _except_ the peers that
    are in the packet's "visited" list. Additionally, it will inject these new
    recepients to the list, popping off the oldest peers.
    """
    MAX_QUEUE_LENGTH = routing.BITCOUNT
    CI_TYPE = MessageType.MSG_CI_BCAST
    RAW_FORMAT = [
        "I",    # the number of hashes in the queue, N
        "%ds",  # the hash queue itself, N-length (injected at runtime)
        "I",    # data length
        "%ds",  # data itself
    ]

    def __init__(self, broadcast_data, outbound, visited=None):
        """ Creates a broadcast packet with intended targets.

        :broadcast_data     the data to broadcast
        :outbound           a list of `Hash` objects indicating who is the
                            intended recepient of the broadcast
        :visited[=None]     a list of `Hash` objects of the previously
                            broadcasted hashes
        """
        self.data = broadcast_data

        if  not isinstance(outbound, (set, list, tuple)) or \
            not all(map(lambda h: isinstance(h, routing.Hash), outbound)):
            raise TypeError("excepted iterable of Hash, got %s/%s" % (
                            type(outbound), type(outbound[0])))

        if visited is not None and not isinstance(visited, (list, tuple)):
            raise TypeError("excepted iterable, got %s" % type(visited))

        self.visited = set()

        # Only store a limited amount of visited peers if total is over the max.
        if visited:
            store_len = BroadcastMessage.MAX_QUEUE_LENGTH - len(outbound)
            store_len = min(store_len, len(visited))
            store_len = len(visited) - store_len    # store latest, not oldest
            self.visited = set(visited[store_len:])

        self.visited = list(self.visited.union(set(outbound)))

    def pack(self):
        packed_hashes = ''.join([
            message.PackedHash(x).pack() for x in self.visited
        ])

        import pdb; pdb.set_trace()
        dlen = len(self.data)
        plen = len(packed_hashes)
        return super(BroadcastMessage, self).pack() + \
               struct.pack('!' + self.FORMAT % (plen, dlen),
                           len(self.visited), packed_hashes,
                           dlen, self.data)

    @classmethod
    def unpack(cls, bs):
        get = lambda f: message.MessageContainer.extract_chunk(f, bs, offset)

        offset = 0
        hashsize = message.PackedHash.MESSAGE_SIZE

        bs = CicadaBaseMessage.unpack(bs)
        vlen,    offset = get(cls.RAW_FORMAT[0])
        voffset         = offset
        visited, offset = get(cls.RAW_FORMAT[1] % (hashsize * vlen))
        dlen,    offset = get(cls.RAW_FORMAT[2])
        data,    offset = get(cls.RAW_FORMAT[3] % dlen)

        visited = [
            message.PackedHash.unpack(bs[i : i + hashsize])[0] \
            for i in xrange(voffset, voffset + len(visited), hashsize)
        ]

        return BroadcastMessage(data, [], visited)

    def __repr__(self):
        return "<BCast | data=%s; seen=%d>" % (
               self.data[:16], len(self.visited))


class DataMessage(CicadaBaseMessage):
    RAW_FORMAT = [
        "I",
        "%ds",
    ]
    CI_TYPE = MessageType.MSG_CI_DATA

    def __init__(self, data):
        super(DataMessage, self).__init__()
        self.data = data

    def pack(self):
        return super(DataMessage, self).pack() + \
               struct.pack('!' + self.FORMAT % len(self.data),
                           len(self.data), self.data)

    @classmethod
    def unpack(cls, bs):
        get = lambda f: message.MessageContainer.extract_chunk(f, bs, offset)

        offset = 0
        bs = CicadaBaseMessage.unpack(bs)
        dlen,   offset = get(cls.RAW_FORMAT[0])
        data,   offset = get(cls.RAW_FORMAT[1] % dlen)

        return DataMessage(data)
