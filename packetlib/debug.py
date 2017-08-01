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
        return ''.join(c if ord(c) >= 32 and ord(c) < 127 else '.' \
                         for c in line)

    for i in xrange(0, len(data), chars):
        row = data[i : i + chars]
        dump = to_hex(row)
        asci = to_string(row)
        print "%s%s %s" % (' ' * indent, dump, asci)


class ProtocolSpecifier:
    def __init__(self, spec):
        if isinstance(spec, ProtocolSpecifier):
            self.raw_format = list(spec.raw_format)
            self.descriptions = tuple(spec.descriptions)
        elif spec and isinstance(spec[0], str):
            self.raw_format = spec
            self.descriptions = tuple("" for x in spec)
        else:
            self.raw_format = list(x[0] for x in spec)
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
        if fmt.raw_format[i].find("%d") != -1:
            tmp_format = fmt.raw_format[i] % 0
        else:
            tmp_format = fmt.raw_format[i]

        chunk_size = struct.calcsize('!' + tmp_format)
        chunk = data[offset : offset + chunk_size]
        offset += chunk_size
        if chunk_size <= 0 or not chunk:
            break

        try:
            unpacked, = struct.unpack('!' + tmp_format, chunk)
            if re.match("\d+s", tmp_format):
                unpacked = ''.join([
                    b if ord(b) >= 32 and ord(b) < 128 else '.' \
                    for b in unpacked
                ])
        except struct.error:
            unpacked = "err," + repr(chunk)

        print "%s | %s -- %s %s" % (fmt.descriptions[i].ljust(desclen),
            fmt_type.ljust(typelen), repr(chunk),
            ("[ %s ]" % repr(unpacked)) if unpacked != chunk and \
                fmt_type.find("str") == -1 else "")

    if len(data) > offset:
        hexdump(data[offset:])
