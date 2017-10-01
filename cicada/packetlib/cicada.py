#!/usr/bin/env python2
""" Defines various packet structures for the higher-level Ciacada protocol.
"""

import struct

from packetlib import message
from chordlib  import routing

class BroadcastMessage(message.BaseMessage):
    """ A raw data packet to broadcast on the network.
    """
    MAX_QUEUE_LENGTH = routing.BITCOUNT

    RAW_FORMAT = [
        "I",    # the number of hashes in the queue, N
        "%ds",  # the hash queue itself, N-length (injected at runtime)
        "I",    # data length
        "%ds",  # data itself
    ]

    def __init__(self, broadcast_data, outbound, visited=None):
        self.data = broadcast_data
        self.visited = []

        # only store a limited amount of visited peers if total is over the max
        if visited:
            store_len = BroadcastMessage.MAX_QUEUE_LENGTH - len(outbound)
            store_len = min(store_len, len(visited))
            store_len = len(visited) - store_len    # store latest, not oldest
            self.visited = self.visited.extend(visited[store_len:])

        self.visited.extend(outbound)

    def pack(self):
        packed_hashes = ''.join([
            message.PackedHash(x).pack() for x in self.visited
        ])

        plen = len(packed_hashes)
        dlen = len(self.data)
        return struct.pack('!' + self.FORMAT % (plen, dlen),
                           len(self.visited), packed_hashes,
                           dlen, self.data)

    @classmethod
    def unpack(cls, bs):
        get = lambda f: message.MessageContainer.extract_chunk(f, bs, offset)

        vlen,    offset = get(self.RAW_FORMAT[0])
        visited, offset = get(self.RAW_FORMAT[1] % vlen)
        dlen,    offset = get(self.RAW_FORMAT[2])
        data,    offset = get(self.RAW_FORMAT[3] % dlen)

        visited = [
            PackedHash.unpack(bs[i : i + len(PackedHash.EMBED_FORMAT)]) \
            for i in xrange(0, len(visited), 4)
        ]

        return BroadcastMessage(data, [], visited)

    def __repr__(self):
        return "<BCast | data=%s; seen=%d>" % (
               self.data[:16], len(self.visited))


class DataMessage(message.BaseMessage):
    pass
