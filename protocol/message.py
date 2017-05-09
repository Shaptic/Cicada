""" Contains packet-layer descriptions of the Cicada protocol.
"""

import sys
import md5
import uuid
import struct

import channel
from   errors import ExceptionType
from   chord import utils


class MessageBlob:
    """ Describes a particular "chunk" in a message.
    """
    MSG_HEADER  = 0
    MSG_PAYLOAD = 1
    MSG_END     = 2


class MessageType:
    """ Describes the various types of messages in the Cicada protocol.
    """
    MSG_CH_JOIN     = 0x0001
    MSG_CH_JOINR    = MSG_CH_JOIN    + 1
    MSG_CH_INFO     = MSG_CH_JOINR   + 1
    MSG_CH_INFOR    = MSG_CH_INFO    + 1
    MSG_CH_NOTIFY   = MSG_CH_INFOR   + 1
    MSG_CH_NOTIFYR  = MSG_CH_NOTIFY  + 1
    MSG_CH_PING     = MSG_CH_NOTIFYR + 1
    MSG_CH_PONG     = MSG_CH_PING    + 1
    MSG_CH_QUIT     = MSG_CH_PONG    + 1
    MSG_CH_ACK      = MSG_CH_QUIT    + 1
    MSG_CH_ERROR    = 0x00FF
    MSG_CH_MAX      = 0x00FF                # last Chord-type message

    MSG_CI_JOIN     = 0xFF00                # first Cicada-type message

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


class QuickType:
    ERROR    = 0x01
    REQUEST  = 0x02
    RESPONSE = 0x04


class UnpackException(Exception):
    """ Represents an exception that occurs when decoding a packet.
    """
    def __init__(self, exc_type, *args):
        super(UnpackException, self).__init__(
            EXCEPTION_STRINGS[exc_type] % args)


class MessageContainer(object):
    """ An abstraction of a raw packet in the Cicada protocol.

    Underlying message types (such as a JOIN message) are stored as raw data.
    This object only provides easy access to header items and packing /
    unpacking of raw bytes.
    """

    CHORD_PR  = "\x63\x68"      # ch
    CICADA_PR = "\x63\x69"      # ci
    VERSION   = "\x00\x01"      # v0.1
    END       = "\x47\x4b\x04"  # GK[EoT]

    RAW_FORMATS = {
        MessageBlob.MSG_HEADER: [
            "2s",   # protocol identifier
            "2s",   # version
            "h",    # message type
            "I",    # sequence number
            "16s",  # checksum
            "I",    # payload length, P
            "B",    # quicker message type
        ],
        MessageBlob.MSG_PAYLOAD: [
            "%ds",  # P-byte payload string, specific to the message type
        ],
        MessageBlob.MSG_END: [
            "B",    # byte-aligned padding length, Z
            "%ds",  # Z padding bytes
            "3s"    # end-of-message
        ],
    }
    FORMATS  = {
        MessageBlob.MSG_HEADER:  ''.join(RAW_FORMATS[MessageBlob.MSG_HEADER]),
        MessageBlob.MSG_PAYLOAD: ''.join(RAW_FORMATS[MessageBlob.MSG_PAYLOAD]),
        MessageBlob.MSG_END:     ''.join(RAW_FORMATS[MessageBlob.MSG_END]),
    }
    DEBUG = {
        "B": "ubyte",
        "H": "ushort",
        "h": "short",
        "Q": "ulong",
        "I": "uint",
        "i": "int",
        "(\d+)s": "\\1-byte str",
        "(\d+)b": "\\1-byte bts",
    }
    HEADER_LEN = struct.calcsize('!' + (FORMATS[MessageBlob.MSG_HEADER]))
    SUFFIX_LEN = struct.calcsize('!' + FORMATS[MessageBlob.MSG_END] % 0)
    MIN_MESSAGE_LEN = utils.nextmul(HEADER_LEN + SUFFIX_LEN, 8)

    @staticmethod
    def quick_type(msg_type):
        if msg_type == MessageType.MSG_CH_ERROR:
            return QuickType.ERROR
        elif msg_type % 2 == 0:
            return QuickType.REQUEST
        return QuickType.RESPONSE

    def __init__(self, msg_type, **kwargs):
        """ Prepares a packet.

        Data is not packaged in any special way; it is just shoved between the
        header and the suffix. The other message objects are responsible for
        packing the data in a specific way.
        """
        self.type = msg_type
        self.data = kwargs.get("data", "")
        self.seq  = kwargs.get("sequence", 0)

    def pack(self):
        """ Packs the packet into a binary format for transfer.
        """
        header = struct.pack(
            '!' + self.FORMATS[MessageBlob.MSG_HEADER],
            self.protocol,
            self.VERSION,
            self.type,
            self.seq,
            '\x00' * 16,
            len(self.data),
            MessageContainer.quick_type(self.type))

        padding = '\x00' * (self.length - self.raw_length)
        suffix = struct.pack(
            '!' + self.FORMATS[MessageBlob.MSG_END] % len(padding),
            len(padding),
            padding,
            self.END)

        packet = header + self.data + suffix
        self.checksum = md5.md5(packet).digest()

        # Inject the checksum into the packet at the right place.
        packet = self._inject_checksum(packet, self.checksum)

        assert len(packet) == self.length, \
               "Expected len=%d, got %d." % (len(packet), self.length)
        return packet

    @classmethod
    def _inject_checksum(cls, packet, checksum):
        header, remainder = (
            packet[ : cls.HEADER_LEN ],
            packet[ cls.HEADER_LEN : ]
        )

        header_blob = cls.RAW_FORMATS[MessageBlob.MSG_HEADER]
        offset = header_blob.index("16s")
        before = struct.calcsize('!' + ''.join(header_blob[:offset]))
        packet = header[:before] + checksum + \
                 header[before + len(checksum):] + remainder

        return packet

    @classmethod
    def unpack(cls, packet):
        """ Unpacks a single full packet from a sequence of raw bytes.

        The assumption is that the entire bytestream makes up a complete and
        correct packet object. If the message is improperly formatted, an
        `UnpackException` is thrown describing what element was missing or
        incorrect.
        """
        if len(packet) < cls.MIN_MESSAGE_LEN:
            raise UnpackException(ExceptionType.EXC_TOO_SHORT, len(packet))

        def getBlob(fmt, data, i):
            """ Extracts a chunk `fmt` out of a packet `data` at index `i`.
            """
            blob_len = struct.calcsize('!' + fmt)
            assert len(data[i:]) >= blob_len, "Invalid blob."
            return (struct.unpack('!' + fmt, data[i : i + blob_len])[0],
                    blob_len + i)

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

        getBlob = lambda i: MessageContainer.extract_chunk(
            header_fmt[i], packet, offset)

        protocol,  offset = getBlob(0)
        version,   offset = getBlob(1)

        if protocol not in (cls.CICADA_PR, cls.CHORD_PR):
            raise UnpackException(ExceptionType.EXC_WRONG_PROTOCOL, protocol)

        if version != cls.VERSION:
            raise UnpackException(ExceptionType.EXC_WRONG_VERSION, version)

        # TODO: Ensure type matches protocol.
        msgtype,   offset = getBlob(2)
        seq_no,    offset = getBlob(3)
        checksum,  offset = getBlob(4)
        payload_sz,offset = getBlob(5)
        quicktype, offset = getBlob(6)

        total_len = utils.nextmul(cls.HEADER_LEN + payload_sz + cls.SUFFIX_LEN, 8)
        if total_len != len(packet):
            raise UnpackException(ExceptionType.EXC_WRONG_LENGTH, total_len,
                                  len(packet))

        # pad_sz,    offset = getBlob(6)
        # pad,       offset = cls.extract_chunk(header_fmt[7] % pad_sz,
        #                                       cicada, offset)
        # if pad != '\x00' * pad_sz:
        #     raise UnpackException(ExceptionType.EXC_BAD_CHECKSUM)

        # TODO: Data length validation.
        data, = struct.unpack(
            "!%ds" % payload_sz,
            packet[start_i + cls.HEADER_LEN : \
                   start_i + cls.HEADER_LEN + payload_sz])

        cicada = MessageContainer(msgtype, data=data, sequence=seq_no)

        # Checksum validation.
        fake_packet = MessageContainer._inject_checksum(packet, '\x00' * 16)
        expected = md5.md5(fake_packet).digest()
        if checksum != expected:
            raise UnpackException(ExceptionType.EXC_BAD_CHECKSUM)

        cicada.checksum = checksum
        print "Checksum:", cicada, repr(cicada.checksum)
        return cicada

    @staticmethod
    def debug_packet(self, data):
        """ Inspects the format and dumps a readable packet representation.

        We have a format, as a list of `struct` specifiers, as well as a debug
        string lookup table. For each format, find the corresponding readable
        equivalent.
        """
        import re
        data = self.pack() if data is None else data

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

    @property
    def raw_length(self):
        return self.HEADER_LEN + len(self.data) + self.SUFFIX_LEN

    @property
    def length(self):
        return utils.nextmul(self.raw_length, 8)

    @property
    def protocol(self):
        return self.CHORD_PR \
            if   self.type <= MessageType.MSG_CH_ERROR \
            else self.CICADA_PR

    @property
    def msg_type(self):
        return self.type

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
        """
        return "%d.%d" % (ord(v[0]), ord(v[1]))

    def __repr__(self): return str(self)
    def __str__(self):
        return "<%s | %d bytes>" % (MessageType.LOOKUP[self.type], self.length)


class FormatMetaclass(type):
    """ Some voodoo; I forgot tbh. """
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

    def __init__(self, msg_type): self.type = msg_type
    def pack(self):     return ""
    def __repr__(self): return str(self)

    @classmethod
    def unpack(cls, pkt):
        # Validate data length.
        if len(pkt) < cls.MESSAGE_SIZE:
            print len(pkt), "too short, need >=", cls.MESSAGE_SIZE

        return BaseMessage()

    @property
    def msg_type(self):
        return self.type

    @property
    def msg_type_str(self):
        return MessageType.LOOKUP[self.msg_type]


EXCEPTION_STRINGS = {
    ExceptionType.EXC_TOO_SHORT: ''.join([
        "Message too small! Expected >= ",
        str(MessageContainer.MIN_MESSAGE_LEN),
        " bytes, got %d bytes." ]),
    ExceptionType.EXC_NO_PREFIX: \
        "No message prefix found! Expected '%s' or '%s' to start packet." % (
            MessageContainer.CHORD_PR, MessageContainer.CICADA_PR),
    ExceptionType.EXC_NO_SUFFIX: \
        "No message end found! Expected '%s' to end packet." % (
            MessageContainer.END),
    ExceptionType.EXC_WRONG_PROTOCOL: ''.join([
        "Unsupported protocol! Expected '",
        MessageContainer.CHORD_PR, "' or '",
        MessageContainer.CICADA_PR,
        "', got '%s'." ]),
    ExceptionType.EXC_WRONG_VERSION: ''.join([
        "Unsupported protocol version! Expected '",
        MessageContainer.version_to_str(MessageContainer.VERSION),
        "', got '%s'." ]),
    ExceptionType.EXC_WRONG_LENGTH: \
        "Incorrect packet length! Expected %d bytes, got %d bytes.",
    ExceptionType.EXC_BAD_CHECKSUM: "Invalid packet checksum!",
}
