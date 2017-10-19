import enum
import socket
import select
import struct
import threading

from ..chordlib  import L
from ..packetlib import message


class ThreadsafeSocket(object):
    """ Provides a thread-safe (and logged) interface into sockets.
    """
    def __init__(self, existing_socket=None):
        self.sendlock = threading.Lock()
        self.socket = existing_socket
        if not self.socket:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def accept(self):
        sock, addr = self.socket.accept()
        return ThreadsafeSocket(sock), addr

    def send(self, *args):
        raise NotImplemented("Use sendall()!")

    def sendall(self, bytestream):
        with self.sendlock:
            self.socket.sendall(bytestream)
            L.debug("Sent %d bytes %s", len(bytestream), repr(bytestream))

    def recv(self, amt):
        L.debug("Waiting on %d bytes ... ", amt)
        data = self.socket.recv(amt)
        L.debug("Received %d bytes from %s:%d: %s", len(data),
                self.socket.getpeername()[0], self.socket.getpeername()[1],
                repr(data))
        return data

    def __getattr__(self, attr):
        if hasattr(self.socket, attr):
            return getattr(self.socket, attr)
        raise AttributeError


class ReadQueue(object):
    """ A queue that combines incoming packets until a complete one is found.

    This is done by continually adding the result of a `socket.read` call until
    the special byte sequence indicating the end of a packet (protocol-specific)
    is found. This is then added to a queue to be processed, _if_ the
    packet can be properly parsed.

    NOTE: Because of the way socket reads are handled, this code is definitely
          specific to Python 2.
    """
    BUFFER_END_BYTES = struct.pack("!%ds" % len(message.MessageContainer.END),
                                   message.MessageContainer.END)

    class PacketState(enum.Enum):
        WAITING = 0
        READING = 1

    def __init__(self):
        self._queue = []
        self._pending = ""
        self._queue_lock = threading.Lock()
        self._pkt_state = ReadQueue.PacketState.WAITING

        formats = message.MessageContainer.RAW_FORMATS
        header_fmt = formats[message.MessageBlob.MSG_HEADER].raw_format
        prev_fmt = header_fmt[:-1]
        upto_resp_fmt = header_fmt[:3]
        self._header_offset = struct.calcsize('!' + ''.join(prev_fmt))
        self._resp_offset   = struct.calcsize('!' + ''.join(upto_resp_fmt))
        self._next_length = 0

    def read(self, data):
        """ Processes some data into the queue.

        This is done in a threadsafe way, because another read may be called
        before this one is processed, if reads are done asynchronously from
        the queueing.
        """
        with self._queue_lock:
            try:
                self._pending += data

                # We are still waiting for the length byte.
                if self._pkt_state == ReadQueue.PacketState.WAITING:
                    n, m = self._header_offset, self._resp_offset
                    if len(self._pending) >= n:
                        length = self._pending[n : n + 4]
                        resp = self._pending[m : m + 1]

                        self._next_resp, = struct.unpack('!?', resp)
                        self._next_length, = struct.unpack('!I', length)
                        self._pkt_state = ReadQueue.PacketState.READING

                if self._pkt_state == ReadQueue.PacketState.READING:
                    base_length = message.MessageContainer.MIN_MESSAGE_LEN
                    if self._next_resp:
                        base_length += message.MessageContainer.RESPONSE_LEN
                    if len(self._pending) == base_length + self._next_length:
                        try:
                            pkt = message.MessageContainer.unpack(self._pending)
                            self._queue.append(pkt)
                        except message.UnpackException:
                            pass

                # index = self._pending.find(self.BUFFER_END_BYTES)
                # if index == -1: return

                # index += len(self.BUFFER_END_BYTES)
                # relevant = self._pending[:index]
                # pkt = message.MessageContainer.unpack(relevant)
                # self._pending = self._pending[index:]
                # if self._pending:
                #     L.debug("Remainder: %s", repr(self._pending))
                # self.queue.append(pkt)

            except message.UnpackException, e:
                import traceback
                from ..packetlib import debug
                print "Failed to parse inbound message:", str(e)
                traceback.print_exc()
                debug.hexdump(self._pending)
                raise

    @property
    def ready(self):
        """ Returns whether or not the queue is ready to be processed. """
        return bool(self._queue)

    def pop(self):
        """ Removes the oldest packet from the queue. """
        with self._queue_lock:
            return self._queue.pop(0)


def validate_socket(fn):
    def wrapper(self, *args, **kwargs):
        if not self.valid or self._socket is None: return False
        try:
            return fn(self, *args, **kwargs)
        except socket.error:
            self.valid = False
            return False

    return wrapper


class PeerSocket(object):
    """ Wraps a socket object for use by a processor.
    """
    def __init__(self, on_send=lambda *args: None):
        super(PeerSocket, self).__init__()
        self._socket = None
        self._local, self._remote = None, None
        self._queue = ReadQueue()
        self.valid = True
        self.hooks = {"send": on_send}

    def create_from_existing(self, existing_socket):
        """ Wraps an existing socket.
        """
        if not isinstance(existing_socket, ThreadsafeSocket):
            raise TypeError("expected ThreadsafeSocket, got %s" % type(
                            existing_socket))

        self._socket = existing_socket
        self._cache_all_properties()

    def bind(self, addr):
        """ Creates a listener socket from an address.
        """
        if not isinstance(addr, tuple) or len(addr) != 2:
            raise TypeError("expected (ip, port), got %s" % type(addr))

        self.valid = True
        self._socket = ThreadsafeSocket()
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind(addr)
        self._socket.listen(5)
        self._cache_local_properties()

    def connect(self, addr):
        """ Connects to `addr`, creating a client socket.
        """
        if not isinstance(addr, tuple) or len(addr) != 2:
            raise TypeError("expected (ip, port), got %s" % type(addr))

        self.valid = True
        self._socket = ThreadsafeSocket()
        self._socket.connect(addr)
        self._cache_all_properties()

    def accept(self):
        """ Accepts a new inbound connection.
        """
        client, addr = self._socket.accept()
        return PeerSocket.create_from_accept(addr, client)

    @validate_socket
    def read(self):
        """ Reads from the socket, if it's valid.

        Also, tries parsing the data in the protocol and adds to the internal
        message queue if a full packet has been processed.
        """
        data = self._socket.recv(message.MessageContainer.MIN_MESSAGE_LEN)

        try:
            self._queue.read(data)

        except message.UnpackException, e:
            L.critical("Failed to process an incoming message: %s", str(e))
            self._queue.pending = ""

        return data

    @validate_socket
    def write(self, data):
        """ Sends all data on the socket.
        """
        self.hooks["send"](self, data)
        self._socket.sendall(data)
        return True

    def pop_message(self):
        return self._queue.pop()

    @property
    def has_messages(self):
        return self._queue.ready

    def fileno(self):
        return self._fileno

    @validate_socket
    def shutdown(self):
        return self._socket.shutdown(socket.SHUT_WR)

    @validate_socket
    def close(self):
        self._local = self._remote = None
        self._fileno = 0
        self._socket.close()

    @validate_socket
    def _cache_local_properties(self):
        self._fileno = self._socket.fileno()
        self.local  = self._socket.getsockname()
        return True

    @validate_socket
    def _cache_all_properties(self):
        self._cache_local_properties()
        self.remote = self._socket.getpeername()

    @staticmethod
    def create_from_accept(remote_address, accepted_socket):
        """ Creates a `PeerSocket` instance from a recently-accepted connection.
        """
        ps = PeerSocket()
        ps.create_from_existing(accepted_socket)
        assert ps.remote == remote_address
        return ps
