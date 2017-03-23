import socket
import sys

def print_args(fn):
    def deco(*args, **kwargs):
        print "Function called:", args, kwargs
        return fn(*args, **kwargs)
    return deco

def hexdump(data, chars=16, indent=4):
    for i in xrange(0, len(data), chars):
        row = data[i:i+chars]
        dump = ' '.join("%02x" % ord(x) for x in row)
        spce = "%s" % (' ' * ((16 * 2) + 15 - len(dump)))
        asci = ''.join('.' if ord(x) < 32 or ord(x) >= 128 else x for x in row)
        print dump, spce, asci

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
