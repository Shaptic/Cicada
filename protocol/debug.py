import socket
import sys


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


class LoggedSocket(socket.socket):
    def __init__(self, logfile=sys.stdout):
        super(LoggedSocket, self).__init__(socket.AF_INET, socket.SOCK_STREAM)
        self.log = logfile

    def sendall(self, bytestream):
        self.log.write("Sending %d bytes '%s' ... " % (
            len(bytestream), repr(bytestream)))
        super(LoggedSocket, self).sendall(bytestream)
        self.log.write("done.\n")
        self.log.flush()

    def recv(self, amt):
        self.log.write("Waiting on %d bytes ... " % amt)
        data = super(LoggedSocket, self).recv(amt)
        self.log.write("Received %d bytes: '%s'" % (len(data), data))
        return data
