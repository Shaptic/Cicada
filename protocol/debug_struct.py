import re
import struct

class ProtocolSpecifier:
    def __init__(self, spec):
        if spec and isinstance(spec[0], str):
            self.raw_format = spec
            self.descriptions = tuple("" for x in spec)
        else:
            self.raw_format = tuple(x[0] for x in spec)
            self.descriptions = tuple(x[1] for x in spec)

    @property
    def format(self):
        return ''.join(self.raw_format)

    def generate(self):
        for i in xrange(len(self.raw_format)):
            yield (self.raw_format[i], self.descriptions[i])

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

raw_header = [
    ("2s", "id"),
    ("2s", "version"),
    ("H",  "type"),
    ("7s", "padding")
]
header = ProtocolSpecifier(raw_header)

def output(data, fmt):
    results = []
    for item in fmt.raw_format:
        # Iterate over every (match, readable) in the outputter.
        for raw, readable in DEBUG.iteritems():

            # If the match matches, replace the \1 with the real length
            # if necessary, then add it to the list.
            m = re.match(raw, item)
            if m:   # matching format!
                result = readable
                if readable.find("\\1") != -1:  # replace with length
                    result = readable.replace("\\1", m.groups(1)[0])
                results.append(result)
                break

        # No matches, so treat it like an erroneous type.
        else: results.append("err")

    desclen = max(len(x) for x in fmt.descriptions)
    typelen = max(len(x) for x in results) + 1

    # Now, build the output from the raw bytes.
    offset = 0  # how far into the data are we?
    for i, fmt_type in enumerate(results):
        chunk_size = struct.calcsize('!' + fmt.raw_format[i])
        chunk = data[offset : offset + chunk_size]
        offset += chunk_size

        try:
            unpacked, = struct.unpack('!' + fmt.raw_format[i], chunk)
            if re.match("\d+s", fmt.raw_format[i]):
                unpacked = ''.join([
                    b if ord(b) >= 32 and ord(b) < 128 else '.' \
                    for b in unpacked
                ])
        except struct.error:
            unpacked = "err," + repr(chunk)

        print "%s | %s -- %s %s" % (fmt.descriptions[i].ljust(desclen),
            fmt_type.ljust(typelen), repr(chunk),
            "[ %s ]" % repr(unpacked) if unpacked != chunk else "")

val = struct.pack('!' + header.format, "gk", "10", 0xaaaa, '\x00\x20\xff\x42\x70\x25\x00')
output(val, header)
