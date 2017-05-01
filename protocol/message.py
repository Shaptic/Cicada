""" Contains packet-layer descriptions of the Cicada protocol.
"""

import sys
import md5
import uuid
import struct

import channel
from   errors import ExceptionType

class MessageBlob:
    MSG_HEADER = 0
    MSG_DATA   = 1
    MSG_SUFFIX = 2

class MessageType:
    """ Describes the various types of messages in the Cicada protocol.
    """
    MSG_CH_JOIN     = 0x01
    MSG_CH_JOINR    = MSG_CH_JOIN    + 1
    MSG_CH_INFO     = MSG_CH_JOINR   + 1
    MSG_CH_INFOR    = MSG_CH_INFO    + 1
    MSG_CH_NOTIFY   = MSG_CH_INFOR   + 1
    MSG_CH_NOTIFYR  = MSG_CH_NOTIFY  + 1
    MSG_CH_PING     = MSG_CH_NOTIFYR + 1
    MSG_CH_PONG     = MSG_CH_PING    + 1
    MSG_CH_QUIT     = MSG_CH_PONG    + 1
    MSG_CH_ACK      = MSG_CH_QUIT    + 1
    MSG_CH_ERROR    = 0xFF

    # A simple constant-to-string conversion table for human-readability.
    LOOKUP = {
        MSG_CH_JOIN:    "JOIN",
        MSG_CH_JOINR:   "JOIN-RESP",
        MSG_CH_NOTIFY:  "NOTIFY",
        MSG_CH_NOTIFYR: "NOTIFY-RESP",
        MSG_CH_INFO:    "INFO",
        MSG_CH_INFOR:   "INFO-RESP",
        MSG_CH_ERROR:   "ERROR",
        MSG_CH_PING:    "PING",
        MSG_CH_PONG:    "PONG",
        MSG_CH_QUIT:    "QUIT",
        MSG_CH_ACK:     "ACK",
    }

class UnpackException(Exception):
    """ Represents an exception that occurs when decoding a packet.
    """
    def __init__(self, exc_type, *args):
        super(UnpackException, self).__init__(
            EXCEPTION_STRINGS[exc_type] % args)

class CicadaMessage(object):
    """ An abstraction of a raw packet in the Cicada protocol.

    Underlying message types (such as a JOIN message) are stored as raw data.
    This object only provides easy access to header items and packing /
    unpacking of raw bytes.
    """

    PROTOCOL = "\x63\x68"
    VERSION  = "\x00\x01"
    END      = "\x47\x40\x04"

    RAW_FORMATS = {
        MessageType.MSG_HEADER: [
            "2s",   # identifier
            "2s",   # version
            "h",    # message type
            "Q",    # sequence number
            "I",    # checksum
            "I",    # payload length, P
            "B",    # header padding length, Z
            "%ds",  # Z padding bytes
            "B",    # quicker message type
        ],
        MessageType.MSG_PAYLOAD: [
            "%ds",  # P-byte payload string, specific to the message type
        ],
        MessageBlob.MSG_END: [
            "3s"    # end-of-message
        ],
    }
    FORMATS  = {
        MessageBlob.MSG_HEADER: ''.join(RAW_FORMATS[MessageBlob.MSG_HEADER]),
        MessageType.MSG_DATA:   ''.join(RAW_FORMATS[MessageType.MSG_DATA]),
        MessageBlob.MSG_END:    ''.join(RAW_FORMATS[MessageBlob.MSG_END]),
    }
    HEADER_LEN = struct.calcsize('!' + (FORMATS[MessageBlob.MSG_HEADER] % 5))
    SUFFIX_LEN = struct.calcsize('!' + FORMATS[MessageBlob.MSG_SUFFIX])
    MIN_MESSAGE_LEN = HEADER_LEN + SUFFIX_LEN

    def __init__(self, msg_type, **kwargs):
        """ Prepares a packet.

        Data is not packaged in any special way; it is just shoved between the
        header and the suffix. The other message objects are responsible for
        packing the data in a specific way.
        """

        self.type = msg_type
        self.data = kwargs.get("data", "")

    def pack(self):
        """ Packs the packet into a binary format for transfer.
        """
        header = struct.pack('!' + self.FORMATS[MessageBlob.MSG_HEADER],
            self.PROTOCOL,
            self.VERSION,
            self.type,
            self.length,
            len(self.data))

        suffix = struct.pack('!' + self.FORMATS[MessageBlob.MSG_SUFFIX],
                             '0' * 16, self.SUFFIX)

        packet = header + self.data + suffix
        self.checksum = md5.md5(packet).digest()
        packet = header + self.data + \
            struct.pack('!' + self.FORMATS[MessageBlob.MSG_SUFFIX],
                        self.checksum, self.SUFFIX)

        assert len(packet) == self.length, \
               "Expected len=%d, got %d." % (len(packet), self.length)

        return packet

    @classmethod
    def unpack(cls, packet):
        """ Unpacks a single `CicadaMessage` from a sequence of raw bytes.

        Returns a 3-tuple of the new object and remaining data that existed
        before and after a whole `CicadaMessage` object (if any). If the message
        is improperly formatted, an `UnpackException` is thrown describing what
        element was missing or incorrect.

        See `UnpackException` for possible errors and their explanations.
        """
        if len(packet) < cls.MIN_MESSAGE_LEN:
            raise UnpackException(ExceptionType.EXC_TOO_SHORT, len(packet))

        # Construct a fake suffix to search the packet for it.
        fake_suffix = struct.pack(
            # just grab the terminator formatting
            "!" + cls.RAW_FORMATS[MessageBlob.MSG_SUFFIX][-1],
            cls.SUFFIX)

        end_i = packet.find(fake_suffix)
        if end_i == -1:
            raise UnpackException(ExceptionType.EXC_NO_SUFFIX)
        end_i += len(fake_suffix)   # first byte of next message (if any)

        # Extract one byte at a time until we match the prefix, which will
        # indicate the beginning of the message.
        index = 0
        prefix_cache = []
        while ''.join(prefix_cache) != cls.PROTOCOL and index < len(packet):
            b = struct.pack("!c", packet[index])

            # Keep a rolling list of bytes that matches the length of the
            # expected prefix string.
            prefix_cache.append(b)
            prefix_cache = prefix_cache[-len(cls.PROTOCOL):]

            index += 1

        if index >= len(packet):
            raise UnpackException(ExceptionType.EXC_NO_PREFIX)

        start_i = index - len(cls.PROTOCOL)

        # Extract an entire message from the raw packet.
        cicada = packet[start_i:end_i]

        def getBlob(fmt, data, i):
            """ Extracts a chunk `fmt` out of a packet `data` at index `i`.
            """
            blob_len = struct.calcsize('!' + fmt)
            assert len(data[i:]) >= blob_len, "Invalid blob."
            return struct.unpack('!' + fmt, data[i : i + blob_len])[0], blob_len + i

        ## Validate the header.
        #
        # We validate the protocol and version, making sure they match the ones
        # we support. Then, we extract message type and store it; no validation
        # is necessary. The length of both the message and the data are
        # validated against the buffer size we've received. Finally, the
        # checksum is validated.
        #
        # TODO: Support multiple versions.
        header_fmt = cls.RAW_FORMATS[MessageBlob.MSG_HEADER]
        offset = 0

        getBlob = lambda i: CicadaMessage.extract_chunk(header_fmt[i], cicada, offset)
        protocol,  offset = getBlob(0)
        version,   offset = getBlob(1)
        msgtype,   offset = getBlob(2)
        total_len, offset = getBlob(3)
        data_len,  offset = getBlob(4)

        if protocol != cls.PROTOCOL:
            raise UnpackException(ExceptionType.EXC_WRONG_PROTOCOL, protocol)

        if version != cls.VERSION:
            raise UnpackException(ExceptionType.EXC_WRONG_VERSION, version)

        if total_len != end_i - start_i:
            raise UnpackException(ExceptionType.EXC_WRONG_LENGTH, total_len, end_i - start_i)

        # TODO: Data length validation.
        data, = struct.unpack(
            "!%ds" % data_len,
            packet[start_i + cls.HEADER_LEN : end_i - cls.SUFFIX_LEN])
        cicada = cls(msgtype)
        cicada.data = data

        # Checksum validation.
        chk, gk = struct.unpack(
            cls.FORMATS[MessageBlob.MSG_SUFFIX],
            packet[end_i - cls.SUFFIX_LEN : end_i])

        all_but_suffix = packet[start_i : end_i - cls.SUFFIX_LEN]
        fake_checksum  = '0' * 16
        after_checksum = packet[end_i - cls.SUFFIX_LEN + 16 : end_i]
        chunk = ''.join([
            all_but_suffix,
            fake_checksum,
            after_checksum
        ])
        checker = md5.md5(chunk).digest()

        if chk != checker:
            raise UnpackException(ExceptionType.EXC_BAD_CHECKSUM)

        cicada.checksum = checker
        print "Checksum:", cicada, repr(checker)
        return (cicada, packet[:start_i], packet[end_i:])

    def _debug(self):
        """ Inspects the format and dumps a readable packet representation.

        We have a format, as a list of `struct` specifiers, as well as a debug
        string lookup table. For each format, find the corresponding readable
        equivalent.
        """
        import re
        data = self.pack()

        # Stores a readable format string for each struct-format.
        results = []

        # Join all of the lists of each sector into one big list.
        all_items = sum(self.RAW_FORMATS.values(), [])

        # Iterate over every struct-format in the packet.
        for item in all_items:

            # Iterate over every (match, readable) in the outputter.
            for fmt, readable in self.DEBUG.iteritems():

                # If the match matches, replace the \1 with the real length
                # if necessary, then add it to the list.
                m = re.match(fmt, item)
                if m:   # matching format!
                    result = readable
                    if readable.find("\\1") != -1:  # replace with length
                        result = readable.replace("\\1", m.groups(1)[0])
                    results.append(result)
                    break

            # No matches, so treat it like an erroneous type.
            else: results.append("errtype")

        print repr(data)
        offset = 0  # how far into the data are we?
        maxlen = "%%%ds" % (max(len(x) for x in results) + 1)
        for i, fmt in enumerate(results):
            item = all_items[i]
            filtered_fmt = item.replace("%d", "0")
            chunk_size = struct.calcsize('!' + filtered_fmt)
            chunk = data[offset : offset + chunk_size]
            offset += chunk_size

            try:
                unpacked, = struct.unpack(filtered_fmt, chunk)
            except struct.error:
                unpacked = "err," + repr(chunk)

            print "%s: %s %s" % (maxlen % fmt, repr(chunk), repr(unpacked))

    @staticmethod
    def extract_chunk(fmt, data, i):
        """ Extracts a chunk `fmt` out of a packet `data` at index `i`.
        """
        blob_len = struct.calcsize('!' + fmt)
        assert len(data[i:]) >= blob_len, "Invalid blob."
        return struct.unpack('!' + fmt, data[i : i + blob_len])[0], blob_len + i

    @staticmethod
    def version_to_str(v):
        """ Converts a 2-byte version blob into a readable string.

        >>> CicadaMessage.version_to_str(CicadaMessage.VERSION)
        '0.1'
        >>> CicadaMessage.version_to_str("\x01\x45")
        '1.69'
        """
        return "%d.%d" % (ord(v[0]), ord(v[1]))

    def __repr__(self): return str(self)
    def __str__(self):
        return "<%s | %d bytes>" % (MessageType.LOOKUP[self.type], self.length)

    @property
    def length(self):
        return self.HEADER_LEN + len(self.data) + self.SUFFIX_LEN

class FormatMetaclass(type):
    def __new__(cls, clsname, bases, dct):
        fmt = ''.join(dct["RAW_FORMAT"])
        dct["FORMAT"] = fmt
        if fmt.find("%d") != -1:
            dct["MESSAGE_SIZE"] = struct.calcsize('!' + fmt % tuple([
                0 for _ in xrange(fmt.count("%d"))
            ]))
        else:
            dct["MESSAGE_SIZE"] = struct.calcsize('!' + fmt)
        return type.__new__(cls, clsname, bases, dct)

class BaseMessage(object):
    """ Base class for all _data_ messages sent using the Cicada protocol.
    """
    __metaclass__ = FormatMetaclass
    RAW_FORMAT = []

    def __init__(self): self.pkt = None
    def pack(self):     return self.pkt.pack()
    def __repr__(self): return str(self)

    @classmethod
    def unpack(cls, pkt):
        obj, pre, post = CicadaMessage.unpack(pkt)

        # Validate data length.
        if len(obj.data) < cls.MESSAGE_SIZE:
            print len(obj.data), "too short, need >=", cls.MESSAGE_SIZE

        return obj, pre, post

class JoinMessage(BaseMessage):
    """ Prepares a JOIN packet.

    Users could be a part of multiple channels, so the JOIN command needs to
    specify which channel to participate in.

    This merely contains the channel ID to join, and a representation of
    ourselves as a user so that the channel owner knows who we are.
    """
    RAW_FORMAT = [
        "%ds" % channel.CHANNEL_ID_LENGTH,
                # unique channel ID
        "I",    # length
        "%ds",  # bytestream of the user
    ]

    def __init__(self, chan, user):
        if not isinstance(chan, channel.ChannelID):
            raise TypeError("Invalid type for channel!")
        if not isinstance(user, str):
            raise TypeError("Invalid type for user!")

        self.pkt = CicadaMessage(MessageType.MSG_JOIN)
        self.pkt.data = struct.pack("!%s" % (self.FORMAT % len(user)),
                                    str(chan), len(user), user)
        self.channel_id = chan
        self.from_user = user

    @classmethod
    def unpack(cls, packet):
        obj, pre, post = BaseMessage.unpack(packet)

        offset = 0
        getBlob = lambda i: CicadaMessage.extract_chunk(
            cls.RAW_FORMAT[i], obj.data, offset)

        chan_id, offset  = getBlob(0)
        user_len, offset = getBlob(1)
        user, offset     = CicadaMessage.extract_chunk(
            cls.RAW_FORMAT[2] % user_len, obj.data, offset)

        j = JoinMessage(channel.ChannelID(chan_id), user)
        j.pkt = obj
        j.from_user = user

        return j, pre, post

    def __str__(self):
        return "<%s | id=%s>" % (MessageType.LOOKUP[self.pkt.type],
            self.channel_id)

class JoinAckMessage(BaseMessage):
    """ Prepares a response to a JOIN packet.

    This includes all relevant channel metadata associated with the ID:
        - readable channel name
        - current number of users, N
        - random selection of log_2(N) neighbors

    The user is the responsible for talking to these neighbors.
    """
    RAW_FORMAT = [
        "%ds" % channel.CHANNEL_ID_LENGTH,
                                    # unique channel ID
        "H",                        # 2-byte name length, LEN
        "%ds",                      # LEN-byte readable channel name
        "I",                        # 4-byte user count
        "H",                        # 2-byte neighbor count
    ]

    def __init__(self, channel_id, channel_name, user_count, neighbor_count):
        if not isinstance(channel_id, channel.ChannelID):
            raise TypeError("Channel ID is not an object.")

        self.pkt = CicadaMessage(MessageType.MSG_JOIN_ACK)
        self.pkt.data = struct.pack(
            "!%s" % (self.FORMAT % len(channel_name)),
            str(channel_id), len(channel_name), channel_name,
            user_count, neighbor_count)

        self.channel_id = channel_id
        self.name = channel_name
        self.users = user_count
        self.neighbors = neighbor_count

    @classmethod
    def unpack(cls, packet):
        obj, pre, post = CicadaMessage.unpack(packet)

        offset = 0
        getBlob = lambda i: CicadaMessage.extract_chunk(cls.RAW_FORMAT[i], obj.data, offset)

        chan_id, offset  = getBlob(0)
        name_len, offset = getBlob(1)
        name, offset     = CicadaMessage.extract_chunk(cls.RAW_FORMAT[2] % name_len, obj.data, offset)
        ucount, offset   = getBlob(3)
        ncount, offset   = getBlob(4)

        obj = JoinAckMessage(channel.ChannelID(chan_id), name, ucount, ncount)
        return obj, pre, post

    def __str__(self):
        return "<%s \"%s\" | id=%s;u=%d/%d>" % (
            MessageType.LOOKUP[self.pkt.type],
            self.name, self.channel_id, self.users, self.neighbors)

class FailMessage(BaseMessage):
    """ Represents a generic failure message, containing details within it.

    This saves the effort of having a unique failure format for each message
    type. Instead, the failure message contains within it these details:
        - Checksum of the message that triggered the failure.
        - The severity of the failure (1=warning, 2=error, 3=fatal)
        - An error message describing the failure.

    On a fatal error, the connection will be closed.
    """
    RAW_FORMAT = [
        "16s",  # 16-byte checksum of the message that caused the error
        "b",    # 1-byte  severity
        "I",    # 4-byte  length of the error message
        "%ds",  # The error message
    ]

    def __init__(self, error_type, error_msg, cause, severity=2):
        if not isinstance(cause.pkt, CicadaMessage) or \
           not hasattr(cause.pkt, "checksum"):
            raise TypeError("Cause must contain a valid packet.")

        self.checksum = cause.pkt.checksum
        self.error_msg = error_msg
        self.severity = severity

        self.pkt = CicadaMessage(error_type)
        self.pkt.data = struct.pack('!' + self.FORMAT,
            self.cause, self.severity,
            len(self.error_msg), self.error_msg)

    @classmethod
    def unpack(cls, pkt):
        obj, pre, post = CicadaMessage.unpack(pkt)

        offset = 0
        getBlob = lambda i: CicadaMessage.extract_chunk(
            obj.data, cls.RAW_FORMAT[i], offset)

        chk, offset = getBlob(0)
        sev, offset = getBlob(1)
        leg, offset = getBlob(2)
        err, offset = CicadaMessage.extract_chunk(
            obj.data, cls.RAW_FORMAT[3] % leg, offset)

        return FailMessage(obj.type, err, chk, sev)

    def __str__(self):
        return "<FAIL | msg=%s>" % (self.error_msg)

EXCEPTION_STRINGS = {
    ExceptionType.EXC_TOO_SHORT: ''.join([
        "Message too small! Expected >= ",
        str(CicadaMessage.MIN_MESSAGE_LEN),
        " bytes, got %d bytes." ]),
    ExceptionType.EXC_NO_PREFIX: \
        "No message prefix found! Expected '%s' to start packet." % (
            CicadaMessage.PROTOCOL),
    ExceptionType.EXC_NO_SUFFIX: \
        "No message end found! Expected '%s' to end packet." % (
            CicadaMessage.SUFFIX),
    ExceptionType.EXC_WRONG_PROTOCOL: ''.join([
        "Unsupported protocol! Expected '",
        CicadaMessage.PROTOCOL,
        "', got '%s'." ]),
    ExceptionType.EXC_WRONG_VERSION: ''.join([
        "Unsupported protocol version! Expected '",
        CicadaMessage.version_to_str(CicadaMessage.VERSION),
        "', got '%s'." ]),
    ExceptionType.EXC_WRONG_LENGTH: \
        "Incorrect packet length! Expected %d bytes, got %d bytes.",
    ExceptionType.EXC_BAD_CHECKSUM: "Invalid packet checksum!",
}
