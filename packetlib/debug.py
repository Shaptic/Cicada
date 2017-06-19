""" Provides useful debugging functionality.
"""

import re
import struct


def hexdump(data, chars=16, indent=0):
    # Converts a line to a space separated hexadecimal string
    # Packs 16 bytes of hex, returns hex string
    def to_hex(line):
        return ' '.join("%02X" % ord(c) for c in line) + ' ' + \
               ' '.join('  ' for i in range(chars - len(line) + 1))

    # Converts a string into printables
    def to_string(line):
        return ''.join(c if ord(c) >= 32 and ord(c) < 127 else '.' for c in line)

    for i in xrange(0, len(data), chars):
        row = data[i : i + chars]
        dump = to_hex(row)
        asci = to_string(row)
        print "%s%s %s" % (' ' * indent, dump, asci)


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


FORMAT_STRINGS = {
    "B": "ubyte",
    "H": "ushort",
    "h": "short",
    "Q": "ulong",
    "I": "uint",
    "i": "int",
    "(\d+)s": "\\1-byte str",
    "(\d+)b": "\\1-byte bts",
}


def dump_packet(data, fmt):
    results = []
    for item in fmt.raw_format:
        # Iterate over every (match, readable) in the outputter.
        for raw, readable in FORMAT_STRINGS.iteritems():

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

if __name__ == '__main__':
    raw_header = [
        ("2s", "id"),
        ("2s", "version"),
        ("H",  "type"),
        ("7s", "padding")
    ]

    header = ProtocolSpecifier(raw_header)
    val = struct.pack('!' + header.format, "gk", "10", 0xaaaa,
                      '\x00\x20\xff\x42\x70\x25\x00')
    dump_packet(val, header)
