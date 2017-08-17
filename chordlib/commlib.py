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
    def __init__(self, send_hook, existing_socket=None):
        self.sendlock = threading.Lock()
        self.socket = existing_socket
        self.on_send = send_hook
        if not self.socket:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def accept(self):
        sock, addr = self.socket.accept()
        return ThreadsafeSocket(self.on_send, sock), addr

    def send(self, *args):
        raise NotImplemented("Use sendall()!")

    def sendall(self, bytestream):
        with self.sendlock:
            self.on_send(self.socket, bytestream)
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
        self._sleep = pause
        self.running = True
        self.setDaemon(True)

    def run(self):
        while self.running:
            self._loop_method()
            time.sleep(self.sleep)

    def _loop_method(self):
        raise NotImplemented

    def stop_running(self):
        self.running = False

    @property
    def sleep(self):
        return self._sleep() if callable(self._sleep) else self._sleep


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
            L.debug("Socket handle: %d", client.fileno())
            self._on_accept(addr, client)

        elif er:
            L.error("An error occurred on the listener socket.")
            self.stop_running()


class SocketProcessor(InfiniteThread):
    """ An event-based socket handler.

    In an infinite loop (see the parent class), we will periodically poll the
    sockets for any data. Incoming data will either be responses to requests
    we've sent out (which we track), new requests from our peers, or one-off
    messages that are neither requests nor responses.

    When you send a request (via a static method), you register a handler with
    the thread for what to do when the response is received. The packets are
    matched by their unique ID. The handler is called when the response is
    received (assuming it's valid).

    See `__init__()` for the various events that we act on with provided
    handlers.
    """

    class RequestResponse(object):
        """ A pair of a sent request and its corresponding response.

        When the response is received (`trigger(...)`), the event is set. No
        checking is done on the response; that should be done at a higher level.

        :message    the request we're sending
        :event      either a callback function or a threading event to trigger
                    when the response is received
        """

        def __init__(self, message, event):
            self.request = message
            self.response = None
            self.event = event

        def trigger(self, receiver, response):
            self.response_socket = receiver
            self.response = response

            # For whatever reason, they made `Event` a function that returns an
            # _Event object, so...
            if isinstance(self.event, threading.Event().__class__):
                self.event.set()
            elif self.event is not None:
                self.event(receiver, self.response)


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

            self.queue = ReadQueue()
            self.handler = request_handler
            self.completed = chutils.FixedStack(24)
            self.pending = []       # [ RequestResponse ]
            self.failed = []        # [ RequestResponse ]

        def finalize(self, msg):
            """ Given a full packet instance, inject the sequence number.
            """
            msg.seq = self.current
            self.current += 1

        def add_request(self, request, event):
            """ Triggers an event when a message receives a response.
            """
            self.pending.append(SocketProcessor.RequestResponse(request, event))

        def complete(self, pair, responder, response):
            """ Signifies that a request-response pair is complete.
            """
            if pair not in self.pending:
                raise ValueError("expected valid pair, not found! %s" % pair)

            self.completed.append(pair)
            self.pending.remove(pair)
            pair.trigger(responder, response)

        def fail(self, pair, responder):
            """ Signifies that a request-response pair has failed.
            """
            if pair not in self.pending:
                raise ValueError("expected valid pair, not found! %s" % pair)

            self.failed.append(pair)
            self.pending.remove(pair)
            pair.trigger(responder, None)


    def __init__(self, parent, on_shutdown, on_error):
        """ Creates a thread instance.

        This manages a set of sockets with particular _generic_ request handler
        functions for each one. These will be called for all messages
        indiscriminantly if there is no message-specific handler for an outbound
        request.

        We are resilient across sockets going down for any reason. There are
        several ways a socket can go "down":

            - recv() returns an empty string, indicating a FIN packet and a
              clean connection break. In this case, we call
              `self.on_shutdown()`, which you must provide at instantiation.

            - an exception is thrown when reading or otherwise processing the
              socket, in which case we call `self.on_error()` with the socket
              that went down. this socket should _not_ be considered valid for
              most operations (like `getpeername()`).

            - the socket appears in the "exceptional conditions" list when
              `select`ing on it. this happens for different reasons on different
              systems, and is treated the same as in the case of exceptions.

        In _all_ of these cases, all pending requests are marked as failed and
        triggered as such. Request handlers should deal with this appropriately.
        The sockets are removed from the internal processing list, and no
        mechanism is provided (intentionally) to remove them manually, but you
        can perform a clean shutdown on them via `shutdown_socket(...)`.

        :on_shutdown    a handler to be called when a socket goes down cleanly,
                        that is, a FIN packet has been received, called like
                        so: `on_shutdown(socket)`.

        :on_error       a handler to be called when a socket goes down
                        unexpectedly, such as because of an exception, called
                        like so: `on_error(socket)`
        """
        super(SocketProcessor, self).__init__(pause=0.1)

        self.sockets = {}   # dict -> { socket: MessageStream }
        self.on_shutdown = on_shutdown
        self.on_error = on_error
        self.logfile = open("comms-%d.log" % int(parent.hash), "w")
        self.parent = parent

    def add_socket(self, peer, on_request):
        """ Adds a new socket to manage.

        :peer           a socket object to read from.
        :on_request     a function that accepts and processes a generic
                        message on the socket.

                on_request(socket_received_on, raw_data_received)

            This is called when data is received but there is no expecting
            handler, as is typically the case for request messages or non-paired
            messages.
        """
        if not isinstance(peer, ThreadsafeSocket):
            raise TypeError("expected socket, got %s" % type(peer))

        if peer in self.sockets:
            L.warning("This socket (%s:%d) is already managed by this "
                      "processor.", *peer.getpeername())
            return

        L.debug("Added %s to processing list (len=%d)",
                repr(peer.getpeername()), len(self.sockets) + 1)

        self.sockets[peer] = SocketProcessor.MessageStream(on_request)

    def shutdown_socket(self, peer):
        """ Cleanly shuts down an existing socket.

        We do this "cleanly" by preventing any further writes to the socket.
        When the other end also shuts down cleanly, we stop processing the
        socket. An exception _will_ be thrown if you try writing on this socket
        again.

        :peer       the socket object to shut down
        :returns    whether or not the socket was shut down

        TODO: Should these be added to a "safe" no-write list?
        """
        if peer not in self.sockets:
            L.warning("Attempted to shut down a socket that we aren't managing")
            return False

        peer.shutdown(socket.SHUT_WR)
        return True

    def prepare_request(self, receiver, message, event):
        """ Adds an event to wait for a response to the given message.

        A request may fail to prepare if the socket doesn't exist in this
        processor. This may happen accidentally, or, for example, when a socket
        closes in a main thread and a secondary thread tries making a request on
        it before the close event is processed. Thus, we don't treat it as fatal
        and only return a `bool`.

        :receiver   the raw socket to receive the response on.
        :message    the MessageContainer object that we're sending.
            To this message, we inject the sequence number based on the current
            stream state (creating a new one if necessary). A packet with a
            matching sequence number to be considered a response.
        :event      the threading event object to signal on receipt.

        :returns    whether or not the request was successfully prepared.
        """
        if receiver not in self.sockets:
            L.warning("Socket not registered with this processor.")
            return False

        stream = self.sockets[receiver]
        stream.finalize(message)    # injects sequence number
        stream.add_request(message, event)
        return True

    def response(self, peer, response):
        """ Sends a response to the given peer.

        The response should already be correlated with the request (by passing
        `original=...` when creating the packet).
        """
        L.debug("Sending response to message: %s", response)
        assert response.is_response, "expected response, got %s" % response
        if response.type != message.MessageType.MSG_CH_PONG:
            self.logfile.write(">>> [resp] @ %d, %s:%s, %s\n" % (
                               time.time(), peer.getsockname()[0],
                               str(peer.getsockname()[1]).ljust(5),
                               repr(response)))
            self.logfile.flush()
        return peer.sendall(response.pack())

    def request(self, peer, msg, on_response, wait_time=None):
        """ Initiates a request on a particular thread.

        :peer               the raw socket to send the message from
        :msg                the MessageContainer to send on the thread socket
        :on_response        the callable to run when the response is received.
                                on_response(receiver_socket, response)
                            the response is `None` if the request fails.
        :wait_time[=None]   in seconds, the amount to wait for a response.
            If it's set to `None`, then we wait an indefinite number of time for
            the response, which is a risky operation as then there's no way to
            cancel it. If set to 0, the request is fired off and `on_response`
            is executed when the response is received later, which will likely
            be in a separate thread.

        :returns        the value of the response handler, if it's called.
                        Otherwise, `False` is returned on timeout.

            If the request cannot be prepared (for ex, if the socket doesn't
            exist), this will throw a `ValueError`.
        """
        if not isinstance(peer, ThreadsafeSocket):
            raise TypeError("expected a threadsafe socket, got %s" % type(peer))

        if not isinstance(msg, message.MessageContainer):
            raise TypeError("expected a MessageContainer, got %s" % type(msg))

        if msg.is_response:
            raise ValueError("expected a request, got `msg.is_response`.")

        # This is signaled when the response is ready.
        evt = on_response if wait_time == 0 else threading.Event()

        # Add this request to the current stream for the peer.
        if not self.prepare_request(peer, msg, evt):
            raise ValueError("The request cannot be prepared on this socket.")

        try:
            # Send the request and wait for the response.
            here, there = peer.getsockname(), peer.getpeername()
            L.debug("Sending message %s:%d -> %s:%d: %s",
                    here[0], here[1], there[0], there[1], msg)
            L.debug("    Sequence number: %d", msg.seq)
            if msg.type != message.MessageType.MSG_CH_PING:
                self.logfile.write(">>> [reqt] @ %d, %s:%s, %s\n" % (
                                   time.time(), peer.getsockname()[0],
                                   str(peer.getsockname()[1]).ljust(5),
                                   repr(msg)))
                self.logfile.flush()
            peer.sendall(msg.pack())

        except socket.error:
            raise ValueError("The request cannot be prepared on this socket.")

        if wait_time == 0:
            L.debug("Triggered fire & forget event, response will be called "
                    "on a different thread.")
            return False

        entry = self.sockets[peer]
        if not evt.wait(timeout=wait_time):
            if wait_time:   # don't show a message if it's intentional
                L.warning("Event expired (timeout=%s).", repr(wait_time))
            return False    # still indicate it, though

        # Find the matching request in the completed table.
        for pair in entry.completed.list:
            if pair.request.seq == msg.seq:
                result = pair.response
                break
        else:
            L.critical("The event was triggered, but the response wasn't found "
                       "in the completed section!")
            return False

        L.debug("Received response for message: %s", repr(result))
        return on_response(peer, result) if on_response else result

    def _loop_method(self):
        """ Reads the sockets periodically and calls request handlers.
        """
        socket_list = self.sockets.keys()
        if not socket_list: return      # easy out on no-op

        readers, _, errors = select.select(socket_list, [], socket_list, 1)

        for sock in errors:
            L.error("Socket[%d] errored out in select(): %s", sock.fileno())
            self.sockets.pop(sock)
            self.on_error(sock)

        for sock in readers:
            L.debug("loop")
            try:
                data = sock.recv(message.MessageContainer.MIN_MESSAGE_LEN)
                if not data:
                    L.info("Socket[%d] got a FIN packet.", sock.fileno())
                    L.debug("closing")
                    sock.close()    # FYI: shutdown(RD) throws b/c no connection
                    L.debug("popping")
                    self.sockets.pop(sock)
                    L.debug("shutdown")
                    self.on_shutdown(sock)
                    continue

            except socket.error, e:
                L.error("Socket errored out during recv(): %s", str(e))
                L.debug("closing err")
                sock.close()
                L.debug("pop err")
                if sock not in self.sockets:
                    L.warning("On socket error, removed a non-existant key?")
                else:
                    self.sockets.pop(sock)
                L.debug("err")
                self.on_error(sock)
                continue

            stream = self.sockets[sock]

            # If reading the packet as a message fails, there may have been some
            # corruption on the endpoint, or someone is intentionally injecting
            # false data. Wipe the `pending` buffer on the queue.
            #
            # TODO: What if someone actually _wants_ to send
            #       `MessageContainer.END`?? Queue processing needs to be
            #       better.
            try:
                stream.queue.read(data)

            except message.UnpackException, e:
                L.critical("Failed to process an incoming message: %s", str(e))
                stream.queue.pending = ""
                continue

            while stream.queue.ready:
                msg = stream.queue.pop()

                L.debug("Full message received: %s", repr(msg))

                if msg.type != message.MessageType.MSG_CH_PONG:
                    self.logfile.write("<<< [mesg] @ %d, %s:%s, %s\n" % (
                                       time.time(), sock.getsockname()[0],
                                       str(sock.getsockname()[1]).ljust(5),
                                       repr(msg)))
                    self.logfile.flush()

                #
                # For responses (they include an "original" member), we call the
                # respective response handler if there's one pending. Otherwise,
                # we call the generic handler.
                #

                if msg.original is None:    # non-response
                    stream.handler(sock, msg)
                    continue

                for pair in stream.pending:
                    if pair.request.seq == msg.original.seq:    # expected!
                        stream.complete(pair, sock, msg)
                        break
                else:
                    stream.handler(sock, msg)   # unexpected :(
