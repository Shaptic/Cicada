import struct
import collections

from chordlib  import fingertable
from packetlib import message
from packetlib import utils as pktutils


class JoinRequest(message.BaseMessage):
    """ Prepares a JOIN request.

    A JOIN packet will include the listener address of the local Chord node that
    is sending out this message. This way, other peers can route through to this
    node.
    """

    TYPE = message.MessageType.MSG_CH_JOIN
    RAW_FORMAT = [
        "I",    # IPv4 address
        "H",    # port
    ]

    def __init__(self, listener_addr):
        if not isinstance(listener_addr, tuple) or len(listener_addr) != 2:
            raise TypeError("Please pass a two-tuple address!")

        super(JoinRequest, self).__init__(self.TYPE)
        self.address = pktutils.ip_to_int(listener_addr[0])
        self.port = listener_addr[1]

    def pack(self):
        return struct.pack('!' + self.FORMAT, self.address, self.port)

    @classmethod
    def unpack(cls, bytestream):
        offset = 0
        get = lambda i: message.MessageContainer.extract_chunk(
            cls.RAW_FORMAT[i], bytestream, offset)

        ip, offset  = get(0)
        port, offset = get(1)

        j = JoinRequest((pktutils.int_to_ip(ip), port))
        return j

    @property
    def listener(self):
        return (pktutils.int_to_ip(self.address), self.port)

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
        "I",    # node ip
        "H",    # node port
        "%ds",  # hash
    ]

    RAW_FORMAT = [
        "H",    # hash length, in bytes (32 for SHA256)
        "%ds" % (fingertable.BITCOUNT / 8),
                # SHA256 hash
        "I",    # listener ip
        "H",    # listener port
        "I",    # number of entries in the table, usually BITCOUNT
        # a single table entry, repeated for the number of spec'd times
        "%ds"
    ]

    ENTRY = collections.namedtuple("Finger", "start end addr hash")
    FAKE_NODE = collections.namedtuple("Node", "local_addr hash")

    def __init__(self, node_hash, listener_addr, finger_table=[]):
        """ Creates internal structures, including a fake finger table.

        :node_hash      a string representing the hash bytes
        :listener_addr  a 2-tuple address -- (IP, port) pair
        :finger_table   a list of `chordlib.fingertable.Finger`-like entries
        """
        super(JoinResponse, self).__init__(self.TYPE)

        if not isinstance(listener_addr, tuple) or len(listener_addr) != 2:
            raise TypeError("Please pass a two-tuple address!")

        if isinstance(node_hash, int):
            node_hash = fingertable.unpack_string(node_hash)

        assert len(node_hash) == (fingertable.BITCOUNT / 8), "Invalid hash size."

        self.node_hash = node_hash
        self.address = pktutils.ip_to_int(listener_addr[0])
        self.port = listener_addr[1]

        self.fingers = []
        for entry in finger_table:
            self.fingers.append(self.ENTRY(entry.start, entry.end,
                entry.node.local_addr, entry.node.hash))

    def pack(self):
        hash_bytes = fingertable.BITCOUNT / 8
        entry_bytes = ''.join([
            struct.pack('!' + (''.join(self.ENTRY_FORMAT) % hash_bytes),
                entry.start, entry.end, pktutils.ip_to_int(entry.addr[0]),
                entry.addr[1], entry.hash
            ) for entry in self.fingers
        ])

        pkt = struct.pack('!' + (self.FORMAT % len(entry_bytes)),
            hash_bytes, self.node_hash, pktutils.ip_to_int(self.listener[0]) \
                if not isinstance(self.listener[0], int) else self.listener[0],
            self.listener[1], len(self.fingers), entry_bytes)

        return pkt

    @classmethod
    def unpack(cls, bytestream):
        offset = 0
        get = lambda idx: message.MessageContainer.extract_chunk(
            cls.RAW_FORMAT[idx], bytestream, offset)

        hash_length, offset = get(0)
        hash_value,  offset = get(1)
        listener_ip, offset = get(2)
        listener_pt, offset = get(3)
        finger_cnt,  offset = get(4)

        offset = 0
        get = lambda idx: message.MessageContainer.extract_chunk(
            cls.ENTRY_FORMAT[idx], bytestream, offset)

        fingers = []
        for i in xrange(finger_cnt):
            interval_st, offset = get(0)
            interval_ed, offset = get(1)
            node_ip,     offset = get(2)
            node_pt,     offset = get(3)
            hash_val,    offset = int(message.MessageContainer.extract_chunk(
                cls.ENTRY_FORMAT[4] % hash_length, bytestream, offset))

            node = cls.FAKE_NODE((pktutils.int_to_ip(node_ip), node_pt), hash_val)
            fingers.append(fingertable.Finger(interval_st, interval_ed, node))

        return JoinResponse(hash_value, (
                                pktutils.int_to_ip(listener_ip),
                                listener_pt
                            ), fingers)

    @property
    def listener(self):
        return (pktutils.int_to_ip(self.address), self.port)


    def __str__(self):
        return "<%s | Node (%s:%d),hash=%s,fingers=%d>" % (
            self.msg_type_str, self.listener[0], self.listener[1],
            self.node_hash[:8], len(self.fingers))


class InfoRequest(message.BaseMessage):
    RAW_FORMAT = []
    TYPE = message.MessageType.MSG_CH_INFO

    def __init__(self):
        super(InfoRequest, self).__init__(self.TYPE)


class InfoResponse(JoinResponse):
    RAW_FORMAT = JoinResponse.RAW_FORMAT
    TYPE = message.MessageType.MSG_CH_INFOR


class Notify(message.BaseMessage):
    RAW_FORMAT = []
    pass


class NotifyResponse(message.BaseMessage):
    RAW_FORMAT = []
    pass


if __name__ == "__main__":
    j = JoinRequest(("127.0.0.1", 5000))
    print j, repr(j.pack())
    k = JoinRequest.unpack(j.pack())
    print k, repr(k.pack())
    x = JoinResponse("a" * (fingertable.BITCOUNT / 8), ("10.0.0.1", 6000))
    print x, repr(x.pack())
    y = JoinResponse.unpack(x.pack())
    print y, repr(y.pack())

    assert j.pack() == k.pack(),  "JoinRequest doesn't [en|de]code right!"
    assert x.pack() == y.pack(), "JoinResponse doesn't [en|de]code right!"

# class JoinAckMessage(BaseMessage):
#     """ Prepares a response to a JOIN packet.

#     This includes all relevant channel metadata associated with the ID:
#         - readable channel name
#         - current number of users, N
#         - random selection of log_2(N) neighbors

#     The user is the responsible for talking to these neighbors.
#     """
#     RAW_FORMAT = [
#         "%ds" % channel.CHANNEL_ID_LENGTH,
#                                     # unique channel ID
#         "H",                        # 2-byte name length, LEN
#         "%ds",                      # LEN-byte readable channel name
#         "I",                        # 4-byte user count
#         "H",                        # 2-byte neighbor count
#     ]

#     def __init__(self, channel_id, channel_name, user_count, neighbor_count):
#         if not isinstance(channel_id, channel.ChannelID):
#             raise TypeError("Channel ID is not an object.")

#         self.pkt = CicadaMessage(MessageType.MSG_JOIN_ACK)
#         self.pkt.data = struct.pack(
#             "!%s" % (self.FORMAT % len(channel_name)),
#             str(channel_id), len(channel_name), channel_name,
#             user_count, neighbor_count)

#         self.channel_id = channel_id
#         self.name = channel_name
#         self.users = user_count
#         self.neighbors = neighbor_count

#     @classmethod
#     def unpack(cls, packet):
#         obj, pre, post = CicadaMessage.unpack(packet)

#         offset = 0
#         getBlob = lambda i: CicadaMessage.extract_chunk(
#             cls.RAW_FORMAT[i], obj.data, offset)

#         chan_id, offset  = getBlob(0)
#         name_len, offset = getBlob(1)
#         name, offset     = CicadaMessage.extract_chunk(
#             cls.RAW_FORMAT[2] % name_len, obj.data, offset)
#         ucount, offset   = getBlob(3)
#         ncount, offset   = getBlob(4)

#         obj = JoinAckMessage(channel.ChannelID(chan_id), name, ucount, ncount)
#         return obj, pre, post

#     def __str__(self):
#         return "<%s \"%s\" | id=%s;u=%d/%d>" % (
#             MessageType.LOOKUP[self.pkt.type],
#             self.name, self.channel_id, self.users, self.neighbors)

# class FailMessage(BaseMessage):
#     """ Represents a generic failure message, containing details within it.

#     This saves the effort of having a unique failure format for each message
#     type. Instead, the failure message contains within it these details:
#         - Checksum of the message that triggered the failure.
#         - The severity of the failure (1=warning, 2=error, 3=fatal)
#         - An error message describing the failure.

#     On a fatal error, the connection will be closed.
#     """
#     RAW_FORMAT = [
#         "16s",  # 16-byte checksum of the message that caused the error
#         "b",    # 1-byte  severity
#         "I",    # 4-byte  length of the error message
#         "%ds",  # The error message
#     ]

#     def __init__(self, error_type, error_msg, cause, severity=2):
#         if not isinstance(cause.pkt, CicadaMessage) or \
#            not hasattr(cause.pkt, "checksum"):
#             raise TypeError("Cause must contain a valid packet.")

#         self.checksum = cause.pkt.checksum
#         self.error_msg = error_msg
#         self.severity = severity

#         self.pkt = CicadaMessage(error_type)
#         self.pkt.data = struct.pack('!' + self.FORMAT,
#             self.cause, self.severity,
#             len(self.error_msg), self.error_msg)

#     @classmethod
#     def unpack(cls, pkt):
#         obj, pre, post = CicadaMessage.unpack(pkt)

#         offset = 0
#         getBlob = lambda i: CicadaMessage.extract_chunk(
#             obj.data, cls.RAW_FORMAT[i], offset)

#         chk, offset = getBlob(0)
#         sev, offset = getBlob(1)
#         leg, offset = getBlob(2)
#         err, offset = CicadaMessage.extract_chunk(
#             obj.data, cls.RAW_FORMAT[3] % leg, offset)

#         return FailMessage(obj.type, err, chk, sev)

#     def __str__(self):
#         return "<FAIL | msg=%s>" % (self.error_msg)
