import threading
import select
import socket
import struct
import random
import time
import sys

import chordlib.utils as chutils
from   chordlib  import L
from   packetlib import message


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

    def __init__(self):
        self.queue = []
        self.pending = ""
        self.queue_lock = threading.Lock()

    def read(self, data):
        """ Processes some data into the queue.

        This is done in a threadsafe way, because another read may be called
        before this one is processed, if reads are done asynchronously from
        the queueing.
        """
        with self.queue_lock:
            try:
                self.pending += data
                index = self.pending.find(self.BUFFER_END_BYTES)
                if index == -1: return

                index += len(self.BUFFER_END_BYTES)
                relevant = self.pending[:index]
                pkt = message.MessageContainer.unpack(relevant)
                self.pending = self.pending[index:]
                if self.pending:
                    L.debug("Remainder: %s", repr(self.pending))
                self.queue.append(pkt)

            except message.UnpackException, e:
                import packetlib.debug
                L.warning("Failed to parse inbound message: %s",
                          repr(self.pending))
                packetlib.debug.hexdump(self.pending)
                raise

    @property
    def ready(self):
        """ Returns whether or not the queue is ready to be processed. """
        return bool(self.queue)

    def pop(self):
        """ Removes the oldest packet from the queue. """
        with self.queue_lock:
            return self.queue.pop(0)

class InfiniteThread(threading.Thread):
    """ An abstract thread to run a method forever until its stopped.
    """
    def __init__(self, pause=0, **kwargs):
        super(InfiniteThread, self).__init__(**kwargs)
        self.sleep = pause
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

    def __init__(self, sock, on_accept, timeout=10):
        """ Creates a thread to listen on a socket.

        :sock           a socket instance that is ready to accept clients.
        :on_accept      a callable handler that is called when clients connect.
                            on_accept(client_address, client_socket)
        :timeout[=10]   how long should we wait (s) for the socket to be ready?
        """
        super(ListenerThread, self).__init__(name="ListenerThread", pause=0.2)

        self._on_accept = on_accept
        self.timeout = timeout
        self.listener = sock

    def _loop_method(self):
        rd, wr, er = select.select([ self.listener ], [], [ self.listener ],
                                   self.timeout)
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
        """ A pair of a sent request and its corresponding response.

        When the response is received (`trigger(...)`), the event is set. No
        checking is done on the response; that should be done at a higher level.
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

            # We make the starting sequence a random value between [1, 2^31),
            # which lets us have a full 2^31 messages before overflowing in the
            # worst case.
            self.base_seq = starting_seq or random.randint(1, 2 ** 31)
            self.current  = self.base_seq

            self.handler = request_handler
            self.complete_requests = chutils.FixedStack(24)
            self.pending_requests = []      # [ RequestResponse ]
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

        def complete(self, pair, responder, response):
            """ Signifies that a request-response pair is complete.
            """
            if pair not in self.pending_requests:
                raise ValueError("expected valid pair, not found! %s" % pair)

            self.complete_requests.append(pair)
            self.pending_requests.remove(pair)
            pair.trigger(responder, response)


    def __init__(self, on_error):
        """ Creates a thread instance.

        This manages a set of sockets with particular _generic_ request handler
        functions for each one. These will be called for all messages
        indiscriminantly if there is no handler for a request you sent.

        :on_error   a generic handler that will be called whenever a socket
                    errors out or is closed. Called like so:

                on_error(socket_erroring_out, graceful=True|False)

            Where `graceful` indicates whether it was a cleanly-closed socket
            (that is, no data was received) or if it was an exception thrown.
        """
        super(SocketProcessor, self).__init__(pause=0.2)

        self.sockets = { }  # dict -> { socket: MessageStream }
        self.on_error = on_error

    def add_socket(self, peer, on_request):
        """ Adds a new socket to manage.

        :peer           a socket object to read from.
        :on_request     a function that accepts and processes a generic
                        message on the socket.

                on_request(socket_received_on, raw_data_received)

            This is called when data is received but there is no expecting
            handler, as is typically the case for request messages.
        """
        if not isinstance(peer, ThreadsafeSocket):
            raise TypeError("expected socket, got %s" % type(peer))

        L.debug("Added %s to processing list", repr(peer.getpeername()))
        self.sockets[peer] = SocketProcessor.MessageStream(on_request)
        L.debug("Processing list: %d", len(self.sockets))

    def close_socket(self, peer):
        """ Closes and removes a socket from being managed.
        """
        if peer not in self.sockets:
            L.warning("The peer is not being managed by this processor.")
            return False

        L.info("Closing connection with peer on %s:%d", peer.getpeername()[0],
               peer.getpeername()[1])

        # Should we close any pending requests here?
        stream = self.sockets.pop(peer)
        peer.shutdown(socket.SHUT_RDWR)
        peer.close()
        return True

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
            import pdb; pdb.set_trace()
            raise ValueError("Socket not registered with this processor.")

        stream = self.sockets[receiver]
        stream.finalize(message)    # inject sequence number
        stream.add_request(message, event)

    def response(self, peer, response):
        """ Sends a response to the given peer.

        The response should already be correlated with the request (by passing
        `original=...` when creating the packet). No validation is done on this.
        """
        L.debug("Sending response to message: %s", response)
        return peer.sendall(response.pack())

    def request(self, peer, msg, on_response, wait_time=None):
        """ Initiates a request on a particular thread.

        :peer               the raw socket to send the message from
        :msg                the MessageContainer to send on the thread socket
        :on_response        the callable to run when the response is received.
                                on_response(receiver_socket, response)
        :wait_time[=None]   in seconds, the amount to wait for a response.
            If it's set to `None`, then we wait an indefinite number of time for
            the response, which is a risky operation as then there's no way to
            cancel it.

        :returns        the value of the response handler, if it's called.
                        Otherwise, `False` is returned on timeout.
        """
        if not isinstance(peer, ThreadsafeSocket):
            raise TypeError("expected a raw (threadsafe) socket, got %s" % (
                str(type(peer))))

        if not isinstance(msg, message.MessageContainer):
            raise TypeError("expected a MessageContainer, got %s" % (
                str(type(msg))))

        evt = threading.Event()     # signaled when response is ready

        # Add this request to the current stream for the peer.
        self.prepare_request(peer, msg, evt)

        # Send the request and wait for the response.
        L.debug("Sending message from %s to %s: %s",
            peer.getsockname(), peer.getpeername(), msg)

        peer.sendall(msg.pack())
        entry = self.sockets[peer]
        if not evt.wait(timeout=wait_time):
            if wait_time:   # don't show a message if it's intentional
                L.warning("Event expired (timeout=%s).", repr(wait_time))
            return False    # still indicate it, though

        # Find the matching request in the completed table.
        for pair in entry.complete_requests.list:
            if pair.request.seq == msg.seq:
                result = pair.response
                break
        else:
            L.critical("The event was triggered, but the response wasn't found "
                "in the completed section!")
            return False

        L.debug("Received response for message: %s", repr(result))
        return on_response(peer, result)

    def _loop_method(self):
        """ Reads the sockets periodically and calls request handlers.
        """
        socket_list = self.sockets.keys()
        if not socket_list: return      # easy out on no-op

        readers, _, errors = select.select(socket_list, [], socket_list, 1)

        for sock in errors:
            self.sockets.pop(sock)
            self.on_error(sock, graceful=False)

        for sock in readers:
            try:
                data = sock.recv(message.MessageContainer.MIN_MESSAGE_LEN)
                if not data:
                    L.debug("A socket was closed (no data)!")
                    self.sockets.pop(sock)
                    self.on_error(sock, graceful=True)
                    continue

            except socket.error, e:
                L.error("Socket errored out during recv(): %s", str(e))
                self.sockets.pop(sock)
                self.on_error(sock, graceful=False)
                continue

            stream = self.sockets[sock]
            stream.queue.read(data)
            while stream.queue.ready:
                msg = stream.queue.pop()
                L.debug("Full message received: %s", repr(msg))

                #
                # For responses (they include an "original" member), we call the
                # respective response handler if there's one pending. Otherwise,
                # both for requests and unexpected responses, we call the
                # generic handler.
                #

                if msg.original is None:
                    stream.handler(sock, msg)
                    continue

                for pair in stream.pending_requests:
                    # FIXME: This is not an efficient way to consider a request
                    #        to be "finished."
                    # if pair.response is not None:
                    #     continue

                    if pair.request.seq == msg.original.seq:
                        stream.complete(pair, sock, msg)
                        break
                else:
                    stream.handler(sock, msg)
