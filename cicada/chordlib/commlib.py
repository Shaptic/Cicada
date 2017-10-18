import threading
import select
import socket
import struct
import random
import time
import sys

from ..chordlib  import utils as chutils
from ..packetlib import chord as chordpkt

from   ..chordlib  import L
from   ..chordlib  import peersocket
from   ..packetlib import message


class ListenerThread(chutils.InfiniteThread):
    """ A thread that waits for new peers to connect.

    When a connection occurs, the new `PeerSocket` is dispatched to a handler
    and the listener continues to accept connections from further clients.
    """
    def __init__(self, sock, on_accept, timeout=10):
        """ Creates a thread to listen on a socket.

        :sock           a socket instance that is ready to accept clients
        :on_accept      a callable handler that is called when clients connect
                            on_accept(PeerSocket)
        :timeout[=10]   how long (s) should we wait for the socket to be ready?
        """
        super(ListenerThread, self).__init__(name="ListenerThread", pause=0.2)

        self._on_accept = on_accept
        self.timeout = timeout
        self.listener = sock

    def _loop_method(self):
        rd, _, er = select.select([self.listener], [], [self.listener],
                                  self.timeout)
        if rd:
            client = self.listener.accept()
            L.info("Incoming peer: %s:%d", *client.remote)
            L.debug("Socket handle: %d", client.fileno())
            self._on_accept(client)

        elif er:
            L.error("An error occurred on the listener socket.")
            self.stop_running()


class SocketProcessor(chutils.InfiniteThread):
    """ An event-based socket handler.

    In an infinite loop, we periodically poll the sockets for data. Incoming
    data will be:
      - responses to requests we've sent out (which we're actively tracking)
      - one-off messages that are neither requests nor responses.
      - new requests from our peers

    When you send a request, you register a handler to be invoked when the
    corresponding response is received, which is matched by the unique request
    packet sequence number.
    """
    class RequestResponse(object):
        """ Pairs a (sent) request with its corresponding (pending) response.

        When the response is "received" (i.e. `trigger(...)` is called), it's
        blindly accepted; validation should be done at a higher level. Then, the
        event object is set, triggering the caller thread (if any).

        :message    the request we're sending
        :event      either a callback function or a `threading.Event` to trigger
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
        def __init__(self, on_request, start_seq=None):
            """ Creates a stream.

            :on_request         a handler that is called there are no message-
                                specific handlers found for a message
            :start_seq[=None]   the sequence number on which to start the
                                stream. If this isn't set, it's set to a random
                                integer.
            """
            super(SocketProcessor.MessageStream, self).__init__()

            # We make the starting sequence a random value between [1, 2^31),
            # which lets us have a full 2^31 messages before overflowing in the
            # worst case.
            self.base_seq = start_seq or random.randint(1, 2 ** 31)
            self.current  = self.base_seq

            self.generic_handler = on_request
            self.completed = chutils.FixedStack(24)
            self.pending, self.failed = [], []       # [ RequestResponse() ]

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


    def __init__(self, on_shutdown, on_error):
        """ Creates a socket processing thread.

        This manages a set of `PeerSocket`s with particular _generic_ request
        handler function for each one. These will be called for all messages
        indiscriminantly if there is no message-specific handler for an outbound
        request.

        We are resilient across sockets going down for any reason, bubbling up
        errors to the parent. There are several ways a socket can go "down":

            - `recv()` returns an empty string, indicating a FIN packet and a
              clean connection break. in this case, we call `on_shutdown`.

            - an exception is thrown when reading or otherwise processing the
              socket, in which case we call `on_error`, passing the socket that
              went down. most operations on this socket will throw (like
              `getpeername()`).

            - the socket appears in the "exceptional conditions" list when
              `select`ing on it. this happens for different reasons on different
              systems, and is treated the same as in the case of exceptions.

        In _all_ of these cases, pending requests are marked as failed and
        triggered as such. Request handlers should deal with this appropriately.
        The sockets are removed from the internal processing list, and no
        mechanism is provided (intentionally) to remove them manually, but you
        can perform a clean shutdown on them via `shutdown_socket(...)`.

        :on_shutdown    a handler to be called when a socket goes down cleanly,
                        that is, a FIN packet has been received, called like
                        so: `on_shutdown(PeerSocket)`

        :on_error       a handler to be called when a socket goes down
                        unexpectedly, such as because of an exception, called
                        like so: `on_error(PeerSocket)`
        """
        super(SocketProcessor, self).__init__(pause=0.1)

        self._peer_streams = {}   # dict -> { PeerSocket: MessageStream }
        self.on_shutdown = on_shutdown
        self.on_error = on_error

    def add_socket(self, peer, on_request):
        """ Adds a new socket to manage.

        :peer           a `PeerSocket` object to read from
        :on_request     a function that accepts and processes a generic
                        message on the socket

                on_request(recv_socket, recv_data)

            This is called when data is received but there is no expecting
            handler, as is typically the case for request messages or non-paired
            messages.
        """
        if not isinstance(peer, peersocket.PeerSocket):
            raise TypeError("expected PeerSocket, got %s" % type(peer))

        if peer in self._peer_streams:
            L.warning("This socket (%s:%d) is already managed by this "
                      "processor.", *peer.remote)
            return

        L.debug("Added %s to processing list (len=%d)",
                repr(peer.remote), len(self._peer_streams) + 1)

        self._peer_streams[peer] = SocketProcessor.MessageStream(on_request)

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
        if peer not in self._peer_streams:
            L.warning("Tried to shutdown a socket that we aren't managing.")
            return False

        peer.shutdown()
        return True

    def prepare_request(self, receiver, message, event):
        """ Adds an event to wait for a response to the given message.

        A request may fail to prepare if the socket doesn't exist in this
        processor. This may happen accidentally, or, for example, when a socket
        closes in a main thread and a secondary thread tries making a request on
        it before the close event is processed. Thus, we don't treat it as fatal
        and only return a `bool`.

        :receiver   the `PeerSocket` to receive the response on
        :message    the `MessageContainer` that we're sending
            To this message, we inject the sequence number based on the current
            stream state. A packet with a matching sequence number is considered
            the response.
        :event      the threading event object to signal on receipt

        :returns    whether or not the request was successfully prepared
        """
        if receiver not in self._peer_streams:
            L.warning("Socket not registered with this processor.")
            return False

        stream = self._peer_streams[receiver]
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
        self._peer_streams[peer].finalize(response)
        return peer.write(response.pack())

    def request(self, peer, msg, on_response, wait_time=None):
        """ Initiates a request.

        :peer               the `PeerSocket` to send the message from
        :msg                the `MessageContainer` to send
        :on_response        the callable to run when the response is received:
                                on_response(receiver_socket, response)
                            the response is `None` if the request fails.
        :wait_time[=None]   the amount to wait for a response, in seconds
            If it's set to `None`, we wait an indefinite amount of time for the
            response. This is risky, since there's no way to cancel it. If set
            to 0, the request is fired off and `on_response` is executed when
            the response is received later, likely be in a separate thread.

        :returns        the return value of the response handler, if it's
                        called. otherwise, `False` is returned on a timeout.

            If the request cannot be prepared (for ex, if the socket is
            invalid), this will throw a `ValueError`.
        """
        if not isinstance(peer, peersocket.PeerSocket):
            raise TypeError("expected a PeerSocket, got %s" % type(peer))

        if not isinstance(msg, message.MessageContainer):
            raise TypeError("expected a MessageContainer, got %s" % type(msg))

        if msg.is_response:
            raise ValueError("expected a request, got a response")

        # This is signaled when the response is ready.
        evt = on_response if wait_time == 0 else threading.Event()

        # Add this request to the current stream for the peer.
        if not self.prepare_request(peer, msg, evt):
            peer.valid = False
            return False

        # Send the request and wait for the response.
        here, there = peer.local, peer.remote
        L.debug("Sending message %s:%d -> %s:%d: %s",
                here[0], here[1], there[0], there[1], msg)
        L.debug("    Sequence number: %d", msg.seq)
        peer.write(msg.pack())

        if wait_time == 0:
            L.debug("Triggered fire & forget event, response will be called "
                    "on a different thread.")
            return False

        stream = self._peer_streams[peer]
        if not evt.wait(timeout=wait_time):
            if wait_time:   # don't show a message if it's intentional
                L.warning("Event expired (timeout=%s).", repr(wait_time))
            return False    # still indicate it, though

        # Find the matching request in the completed table.
        for pair in stream.completed.list:
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
        valid_sockets = filter(lambda ps: ps.valid, self._peer_streams)
        readers, _, errors = select.select(valid_sockets, [], valid_sockets, 1)

        for sock in errors:
            L.error("Socket[%d] errored out in select(): %s", sock.fileno())
            # self._peer_streams.pop(sock)
            self.on_error(sock)

        for peersock in readers:
            peersock.read()

            while peersock.has_messages:
                msg = peersock.pop_message()
                stream = self._peer_streams[peersock]
                L.debug("Full message received: %s", repr(msg))

                #
                # For responses (they include an "original" member), we call the
                # respective response handler if there's one pending. Otherwise,
                # we call the generic handler.
                #

                if msg.original is None:                        # non-response
                    stream.generic_handler(peersock, msg)
                    continue

                for pair in stream.pending:
                    if pair.request.seq == msg.original.seq:    # expected!
                        stream.complete(pair, peersock, msg)
                        break
                else:
                    stream.generic_handler(peersock, msg)       # unexpected :(

            if not peersock.valid:      # notify higher layer on errors
                L.error("PeerSocket (#%d) errored out." % peersock.fileno())
                self.on_shutdown(peersock)

        self._peer_streams = dict(filter(lambda pair: pair[0].valid,
                                         self._peer_streams.iteritems()))
