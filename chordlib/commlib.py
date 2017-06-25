import threading
import select
import socket
import struct
import random
import time
import sys

import chordlib.utils   as     chutils
from   chordlib         import L
from   packetlib        import message


class ThreadsafeSocket(object):
    """ Provides a thread-safe interface into sockets.

    Additionally, it performs logging on send/receive operations.
    """

    def __init__(self, existing_socket=None):
        self.socket = existing_socket
        if not self.socket:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def accept(self):
        sock, addr = self.socket.accept()
        return ThreadsafeSocket(sock), addr

    def send(self, *args):
        raise NotImplemented("Use sendall()!")

    def sendall(self, bytestream):
        with threading.Lock() as lock:
            self.socket.sendall(bytestream)
            L.debug("Sent %d bytes %s ... ", len(bytestream), repr(bytestream))

    def recv(self, amt):
        L.debug("Waiting on %d bytes ... ", amt)
        data = self.socket.recv(amt)
        L.debug("Received %d bytes: %s", len(data), repr(data))
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

    def __init__(self):
        self.queue = []
        self.pending = ""

    def read(self, data):
        """ Processes some data into the queue.
        """
        with threading.Lock() as queue_lock:
            self.pending += data
            index = self.pending.find(self.BUFFER_END_BYTES)
            if index == -1: return

            try:
                pkt = message.MessageContainer.unpack(self.pending)
                self.queue.append(pkt)
                self.pending = self.pending[index + len(self.BUFFER_END_BYTES):]

            except message.UnpackException, e:
                L.warning("Failed to parse incoming message: %s", repr(self.pending))
                message.MessageContainer.debug_packet(self.pending)
                raise

    @property
    def ready(self):
        """ Returns whether or not the queue is ready to be processed. """
        return bool(self.queue)

    def pop(self):
        """ Removes the oldest packet from the queue. """
        return self.queue.pop(0)


class SignalableThread(threading.Thread):
    """ A utility base thread to run a signal function when something happens.
    """

    def __init__(self, on_ready, **kwargs):
        super(SignalableThread, self).__init__(**kwargs)
        self.handler = on_ready

    def signal(self):
        self.handler(self)


class InfiniteThread(threading.Thread):
    """ A utility base thread to run a method forever until its signalled.

    >>> import time
    >>> class Test(InfiniteThread):
    ...     def _loop_method(self):
    ...         time.sleep(1)
    ...         print 1
    ...
    >>> tester_thread = Test()
    >>> tester_thread.start()
    >>> tester_thread.stop_running()
    >>> tester_thread.join(1000)
    1
    """

    def __init__(self, pause_length=0, **kwargs):
        super(InfiniteThread, self).__init__(**kwargs)
        self.sleep = pause_length
        self.running = True
        self.setDaemon(True)

    def run(self):
        while self.running:
            self._loop_method()
            if self.sleep:
                time.sleep(self.sleep)

    def _loop_method(self):
        raise NotImplemented

    def stop_running(self):
        self.running = False


class ListenerThread(InfiniteThread):
    """ A thread to wait for a new `Peer` to connect to this node.

    When a connection occurs, a `Peer` object is created from the joined socket.
    After the connection is established, the socket will still continue to
    accept connections from further clients.
    """
    TIMEOUT = 10     # how long should we wait for the socket to be ready?

    def __init__(self, sock, on_accept):
        """ Creates a thread to listen on a socket.

        :sock       A socket instance that is ready to accept clients.
        :on_accept  A callable handler that is called when clients connect.
                        on_accept(client_address, client_socket)
        """
        super(ListenerThread, self).__init__(name="ListenerThread")
        self._on_accept = on_accept
        self.listener = sock

    def _loop_method(self):
        rd, wr, er = select.select([ self.listener ], [], [ self.listener ],
                                   ListenerThread.TIMEOUT)
        if rd:
            client, addr = self.listener.accept()
            L.info("Incoming peer: %s:%d", addr[0], addr[1])
            self._on_accept(addr, client)

        elif er:
            L.error("An error occurred on the listener socket.")
            self.stop_running()


class SocketProcessor(InfiniteThread):
    """ An event-based socket handler.

    In an infinite loop (see the parent class), we will periodically poll the
    sockets for any data. This will either be a response to a request that a
    socket sent out, or a new request that we're sending out from a particular
    socket.

    When you send a request (via a static method), you register a handler with
    the thread for what to do when the response is received. The packets are
    matched by their unique ID. Within a certain time period, if a matching
    response is received, the handler is called.
    """

    class RequestResponse(object):
        """ A pair for the sent request and its response.
        """
        def __init__(self, message, event=None):
            self.request = message
            self.response = None
            self.event = event

        def trigger(self, receiver, response):
            self.response_socket = receiver
            self.response = response
            if self.event is not None: self.event.set()

    class MessageStream(object):
        """ A one-way series of messages with increasing sequence numbers.
        """
        def __init__(self, request_handler, starting_seq=None):
            super(SocketProcessor.MessageStream, self).__init__()

            self.base_seq = starting_seq or random.randint(1, 2 ** 32 - 1)
            self.current  = self.base_seq

            self.handler = request_handler
            self.pending_requests = []
            self.queue = ReadQueue()

        def finalize(self, msg):
            """ Given a full packet instance, inject the sequence number.
            """
            msg.seq = self.current
            self.current += 1

        def add_request(self, request, event):
            """ Triggers an event when a message receives a response.
            """
            self.pending_requests.append(
                SocketProcessor.RequestResponse(request, event))

    def __init__(self, on_error):
        """ Creates a thread instance.

        This manages a set of sockets with particular _generic_ request handler
        functions for each one. These will be called for all messages
        indiscriminantly if there is no handler for a request you sent.

        :on_error   A generic handler that will be called whenever a socket
                    errors out or is closed. Called like so:

                on_error(socket_erroring_out, graceful=True|False)

            Where `graceful` indicates whether it was a cleanly-closed socket
            (that is, no data was received) or if it was an exception thrown.
        """
        super(SocketProcessor, self).__init__()

        # dict -> { socket: MessageStream }
        self.sockets = { }
        self.on_error = on_error

    def add_socket(self, peer_socket, on_request):
        """ Adds a new socket to manage.

        :peer_socket    A socket object to read from.
        :on_request     A function that accepts and processes a generic
                        message on the socket.

            This is called when data is received but there is no expecting
            handler. It is called with these args:
                on_request(socket_received_on, raw_data_received)
        """
        if not isinstance(peer_socket, ThreadsafeSocket):
            raise TypeError("Initialized processor thread without socket.")

        L.debug("Added %s to processing list", repr(peer_socket.getpeername()))
        self.sockets[peer_socket] = SocketProcessor.MessageStream(on_request)

    def prepare_request(self, receiver, message, event):
        """ Adds an event to wait for a response to the given message.

        :receiver   the raw socket to receive the respone on
        :message    the MessageContainer object that we're sending.
            To this message, we inject the sequence number based on the current
            stream state (creating a new one if necessary). A packet with a
            matching sequence number to be considered a response.
        :event      the threading event object to signal on receipt.
        """
        if receiver not in self.sockets:
            raise ValueError("Socket not registered with this processor.")

        stream = self.sockets[receiver]
        stream.finalize(message)
        stream.add_request(message, event)

    def _loop_method(self):
        """ Reads the sockets periodically and calls request handlers.
        """
        socket_list = self.sockets.keys()
        if not socket_list: return

        rd, _, er = select.select(socket_list, [], socket_list, 1)

        for sock in er:
            self.sockets.pop(sock)
            self.on_error(sock, graceful=False)

        for sock in rd:
            try:
                data = sock.recv(message.MessageContainer.MIN_MESSAGE_LEN)
                if not data:
                    L.debug("A socket was closed (no data)!")
                    self.sockets.pop(sock)
                    self.on_error(sock, graceful=True)
                    continue

            except socket.error, e:
                L.error("Socket errored out during select(): %s", str(e))
                self.sockets.pop(sock)
                self.on_error(sock, graceful=False)
                continue

            L.debug("Received raw message from %s: %s",
                repr(sock.getpeername()), repr(data))

            stream = self.sockets[sock]
            stream.queue.read(data)
            while stream.queue.ready:
                msg = stream.queue.pop()
                L.debug("Full message received: %s", repr(msg))

                # For responses (they include an "original" member), we call the
                # respective response handler if there's one pending. Otherwise,
                # both for requests and unexpected responses, we call the
                # generic handler.

                if msg.original is None:
                    stream.handler(sock, msg)
                    continue

                for pair in stream.pending_requests:
                    # FIXME: This is not an efficient way to consider a request
                    #        to be "finished."
                    # if pair.response is not None:
                    #     continue

                    if pair.request.seq == msg.original.seq:
                        pair.trigger(sock, msg)
                        # stream.pending_requests.remove(pair)
                        break
                else:
                    stream.handler(sock, msg)

    def response(self, peer, response):
        """ Sends a response to the given peer, correlated with the request.
        """
        L.debug("Sending response to message: %s", response)
        data = response.pack()
        return peer.sendall(data)

    def request(self, peer, msg, on_response, wait_time=None):
        """ Initiates a request on a particular thread.

        :peer               the raw socket to send the message from
        :msg                the MessageContainer to send on the thread socket
        :on_response        the callable to run when the response is received.
                                on_response(receiver_socket, response)
        :wait_time[=None]  in seconds, the amount to wait for a response.
            If it's set to None, then we wait an indefinite number of time for
            the response, which is a risky operation as then there's no way to
            cancel it.

        :returns        the value of the response handler, if it's called.
                        Otherwise, `False` is returned on timeout.
        """
        if not isinstance(peer, ThreadsafeSocket):
            raise TypeError("request() requires a raw socket.")

        if not isinstance(msg, message.MessageContainer):
            raise TypeError("request() requires a proper MessageContainer.")

        evt = threading.Event()     # signaled when response is ready

        # Add this request to the current stream for the peer.
        self.prepare_request(peer, msg, evt)

        # Send the request and wait for the response.
        L.debug("Sending message from %s to %s: %s",
            peer.getsockname(), peer.getpeername(), msg)

        peer.sendall(msg.pack())
        entry = self.sockets[peer]
        if not evt.wait(timeout=wait_time):
            if wait_time:   # no message if intentional timeout
                L.warning("Event expired (timeout=%s).", repr(wait_time))
            return False

        # TODO: The -1 access is a race condition.
        L.debug("Received response for message: %s", repr(
            entry.pending_requests[-1].response))

        return on_response(peer, entry.pending_requests[-1].response)
