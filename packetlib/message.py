""" Contains packet-layer descriptions of the Cicada protocol.
"""

import sys
import md5
import uuid
import enum
import struct
import collections

from packetlib.errors import ExceptionType

from packetlib import debug
from chordlib  import L
from chordlib  import utils as chutils


class MessageBlob(enum.Enum):
    """ Describes a particular "chunk" in a message.
    """
    MSG_HEADER      = 0     # used in all messages
    MSG_RESPONSE    = 1     # only in responses, describes original request
    MSG_PAYLOAD     = 2     # packet data
    MSG_END         = 3     # suffix to indicate message termination


class MessageType(object):
    """ Describes the various types of messages in the Cicada protocol.
    """
    MSG_CH_JOIN     = 0x0001
    MSG_CH_INFO     = MSG_CH_JOIN   + 1
    MSG_CH_NOTIFY   = MSG_CH_INFO   + 1
    MSG_CH_LOOKUP   = MSG_CH_NOTIFY + 1
    MSG_CH_PING     = MSG_CH_LOOKUP + 1
    MSG_CH_PONG     = MSG_CH_PING   + 1
    MSG_CH_QUIT     = MSG_CH_PONG   + 1
    MSG_CH_ACK      = MSG_CH_QUIT   + 1
    MSG_CH_ERROR    = 0x00FF
    MSG_CH_MAX      = 0x00FF                # last Chord-type message

    MSG_CI_JOIN     = 0xFF00                # first Cicada-type message

    # A simple constant-to-string conversion table for human-readability.
    LOOKUP = {
        MSG_CH_JOIN:    "JOIN",
        MSG_CH_NOTIFY:  "NOTIFY",
        MSG_CH_LOOKUP:  "LOOKUP",
        MSG_CH_INFO:    "INFO",
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


class MessageContainer(object):
    """ An abstraction of a raw packet in the Cicada protocol.

    Underlying message types (such as a JOIN message) are stored as raw data.
    This object only provides easy access to header items and packing /
    unpacking of raw bytes.
    """
    FAKE_RESP = collections.namedtuple("FakeResponse", "seq checksum")

    CHORD_PR  = "\x63\x68"      # ch
    CICADA_PR = "\x63\x69"      # ci
    VERSION   = 0x0002          # v0.2
    END       = "\x47\x4b\x04"  # GK[EoT]

    RAW_FORMATS = {
        MessageBlob.MSG_HEADER: debug.ProtocolSpecifier([
            ("2s",   "protocol identifier"),
            ("h",    "version"),
            ("h",    "message type"),
            ("?",    "response indication"),
            ("I",    "sequence number"),
            ("16s",  "checksum"),
            ("I",    "payload length, P"),
        ]),
        MessageBlob.MSG_RESPONSE: debug.ProtocolSpecifier([
            ("I",    "sequence number of request"),
            ("16s",  "checksum of request"),
        ]),
        MessageBlob.MSG_PAYLOAD: debug.ProtocolSpecifier([
            ("%ds",  "P-byte payload string")
        ]),
        MessageBlob.MSG_END: debug.ProtocolSpecifier([
            ("B",    "byte-aligned padding length, Z"),
            ("%ds",  "Z padding bytes"),
            ("3s",   "end-of-message"),
        ]),
    }
    FORMATS  = {
        MessageBlob.MSG_HEADER:   RAW_FORMATS[MessageBlob.MSG_HEADER].format,
        MessageBlob.MSG_RESPONSE: RAW_FORMATS[MessageBlob.MSG_RESPONSE].format,
        MessageBlob.MSG_PAYLOAD:  RAW_FORMATS[MessageBlob.MSG_PAYLOAD].format,
        MessageBlob.MSG_END:      RAW_FORMATS[MessageBlob.MSG_END].format,
    }
    HEADER_LEN   = struct.calcsize('!' + FORMATS[MessageBlob.MSG_HEADER])
    RESPONSE_LEN = struct.calcsize('!' + FORMATS[MessageBlob.MSG_RESPONSE])
    SUFFIX_LEN   = struct.calcsize('!' + FORMATS[MessageBlob.MSG_END] % 0)
    MIN_MESSAGE_LEN = chutils.nextmul(HEADER_LEN + SUFFIX_LEN, 8)

    def __init__(self, msg_type, data="", sequence=0, original=None):
        """ Prepares a packet.

        Data is not packaged in any special way; it is just shoved between the
        header and the suffix. The other message objects are responsible for
        packing the data in a specific way.

        :msg_type   `MessageType` specification of this message
        :data       raw data to place inside of the packet
        :sequence   sequence number of the packet
        :original   the message being responded to, which indicates that this is
                    a response message
        """
        self.type = msg_type
        self.data = data
        self.seq  = sequence
        self.original = original

    def pack(self):
        """ Packs the packet into a binary format for transfer.
        """
        header = struct.pack(
            '!' + self.FORMATS[MessageBlob.MSG_HEADER],
            self.protocol,
            self.VERSION,
            self.msg_type,
            self.is_response,
            self.seq,
            '\x00' * 16,
            len(self.data))

        if self.is_response:
            header += struct.pack(
                '!' + self.FORMATS[MessageBlob.MSG_RESPONSE],
                self.original.seq,
                self.original.checksum)

            self.HEADER_LEN = MessageContainer.HEADER_LEN + self.RESPONSE_LEN
            assert len(header) == self.HEADER_LEN, "invalid header length?"

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
               "expected len=%d, got %d." % (len(packet), self.length)
        return packet

    @classmethod
    def _inject_checksum(cls, packet, checksum):
        header, remainder = (
            packet[ : cls.HEADER_LEN ],
            packet[ cls.HEADER_LEN : ]
        )

        header_blob = cls.RAW_FORMATS[MessageBlob.MSG_HEADER].raw_format
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

        ## Validate the header.
        header_fmt = cls.RAW_FORMATS[MessageBlob.MSG_HEADER].raw_format
        offset = 0

        get = lambda i: MessageContainer.extract_chunk(
            header_fmt[i], packet, offset)

        protocol,  offset = get(0)
        version,   offset = get(1)

        if protocol not in (cls.CICADA_PR, cls.CHORD_PR):
            raise UnpackException(ExceptionType.EXC_WRONG_PROTOCOL, protocol)

        if version != cls.VERSION:
            raise UnpackException(ExceptionType.EXC_WRONG_VERSION, version)

        # TODO: Ensure type matches protocol.
        msgtype,   offset = get(2)
        is_resp,   offset = get(3)
        seq_no,    offset = get(4)
        checksum,  offset = get(5)
        payload_sz,offset = get(6)

        resp = None
        data_offset = cls.HEADER_LEN
        total_len = data_offset + payload_sz + cls.SUFFIX_LEN

        if is_resp:
            data_offset += cls.RESPONSE_LEN
            total_len += cls.RESPONSE_LEN

            get2 = lambda i: MessageContainer.extract_chunk(
                cls.RAW_FORMATS[MessageBlob.MSG_RESPONSE].raw_format[i],
                packet, offset)

            seq, offset = get2(0)
            chk, offset = get2(1)
            resp = cls.FAKE_RESP(seq, chk)

        total_len  = chutils.nextmul(total_len, 8)
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
            packet[data_offset : data_offset + payload_sz])

        cicada = MessageContainer(msgtype, data=data, sequence=seq_no,
                                           original=resp)

        # Checksum validation.
        fake_packet = MessageContainer._inject_checksum(packet, '\x00' * 16)
        expected = md5.md5(fake_packet).digest()
        if checksum != expected:
            raise UnpackException(ExceptionType.EXC_BAD_CHECKSUM)

        cicada.checksum = checksum
        L.debug("Checksum for %s: %s", cicada, repr(cicada.checksum))
        return cicada

    def dump(self):
        """ Attempts to dump the packet in a readable format.
        """
        from packetlib import debug as D
        fmts = [self.RAW_FORMATS[MessageBlob.MSG_HEADER]]
        if self.is_response: fmt.append(RAW_FORMATS[MessageBlob.MSG_RESPONSE])

        pay = D.ProtocolSpecifier(self.RAW_FORMATS[MessageBlob.MSG_PAYLOAD])
        pay.raw_format[0] = pay.raw_format[0] % len(self.data)
        fmts.append(pay)

        padlen = self.length - self.raw_length
        end = D.ProtocolSpecifier(self.RAW_FORMATS[MessageBlob.MSG_END])
        end.raw_format[1] = end.raw_format[1] % padlen
        fmts.append(end)

        chunks, desc = (sum([fmt.raw_format for fmt in fmts], []),
                        sum([list(fmt.descriptions) for fmt in fmts], []))
        D.dump_packet(self.pack(), D.ProtocolSpecifier(zip(chunks, desc)))

    @staticmethod
    def full_format():
        """ Calculates a simple format for trying to decipher a packet.
        """
        fmts = [
            MessageContainer.RAW_FORMATS[MessageBlob.MSG_HEADER],
            MessageContainer.RAW_FORMATS[MessageBlob.MSG_PAYLOAD],
            MessageContainer.RAW_FORMATS[MessageBlob.MSG_END],
        ]
        chunks, desc = (sum([fmt.raw_format for fmt in fmts], []),
                        sum([list(fmt.descriptions) for fmt in fmts], []))

        import packetlib.debug as D
        return D.ProtocolSpecifier(zip(chunks, desc))

    @property
    def raw_length(self):
        return self.HEADER_LEN + len(self.data) + self.SUFFIX_LEN

    @property
    def length(self):
        return chutils.nextmul(self.raw_length, 8)

    @property
    def protocol(self):
        return self.CHORD_PR \
            if   self.type <= MessageType.MSG_CH_ERROR \
            else self.CICADA_PR

    @property
    def msg_type(self):
        return self.type

    @property
    def is_response(self):
        return self.original is not None

    @staticmethod
    def extract_chunk(fmt, data, i, keep_chunks=False):
        """ Extracts a chunk `fmt` out of a packet `data` at index `i`.
        """
        blob_len = struct.calcsize('!' + fmt)
        assert len(data[i:]) >= blob_len, "Invalid blob."
        unpack = struct.unpack('!' + fmt, data[i : i + blob_len])
        return unpack[0] if not keep_chunks else unpack, blob_len + i

    @staticmethod
    def version_to_str(v):
        """ Converts a 2-byte version short into a readable string.
        """
        return "%d.%d" % (v & 0xFF00 >> 2, v & 0x00FF)

    def __repr__(self): return str(self)
    def __str__(self):
        return "<%s(%dB)%s>" % (
            MessageType.LOOKUP[self.type], self.length,
            (" | to=%d" % self.original.seq) if self.is_response else "")


class FormatMetaclass(type):
    """ Injects runtime definitions into the class.

    Specifically, this is what happens:
        - `RAW_FORMAT`, a list of `struct` formatters, is turned into a
          contiguous string called `FORMAT`.

        - `MESSAGE_SIZE` is defined as the length, in bytes, of this
          specification. If any of the objects in `FORMAT` take a variable size,
          such as variable-length strings (which could, for example, be defined
          as "str:H:%ds"), they are assumed to be zero-length. Thus, it's more
          accurate to say `MIN_MESSAGE_SIZE`, I guess.

        - `EMBED_FORMAT` is defined as a raw byte-format for the message, if you
          were to inject the raw thing into another message (without any regard
          for byte-packing). This is just a `MESSAGE_SIZE`-length bytestring.
    """
    def __new__(cls, clsname, bases, dct):
        fmt = ''.join(dct["RAW_FORMAT"])
        dct["FORMAT"] = fmt
        if fmt.find("%d") != -1:
            dct["MESSAGE_SIZE"] = struct.calcsize('!' + fmt % tuple([
                0 for _ in xrange(fmt.count("%d"))
            ]))
        else:
            dct["MESSAGE_SIZE"] = struct.calcsize('!' + fmt)
        dct["EMBED_FORMAT"] = "%ds" % dct["MESSAGE_SIZE"]

        return type.__new__(cls, clsname, bases, dct)


class BaseMessage(object):
    """ Base class for all _data_ messages sent using the Cicada protocol.
    """
    __metaclass__ = FormatMetaclass
    RAW_FORMAT = []
    RESPONSE = False

    def __init__(self, msg_type):
        self.type = msg_type

    def pack(self): return ""

    @classmethod
    def unpack(cls, pkt):
        # Validate data length.
        if len(pkt) < cls.MESSAGE_SIZE:
            print len(pkt), "too short, need >=", cls.MESSAGE_SIZE

        return BaseMessage()

    @classmethod
    def make_packet(cls, *args, **kwargs):
        if "original" in kwargs and not cls.RESPONSE or \
           cls.RESPONSE and "original" not in kwargs:
            raise ValueError("unexpected %soriginal kwarg in %sresponse "
                "packet type %s" % (
                    "lack of " if "original" not in kwargs else "",
                    "non-" if not cls.RESPONSE else "",
                    MessageType.LOOKUP[cls.TYPE]))

        return MessageContainer(cls.TYPE, data=cls(*args).pack(), **kwargs)

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
