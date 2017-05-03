import threading
import socket
import select
import time

from . import utils


class protocol:
    """ TODO: Move and formalize this.
    """
    MIN_MESSAGE_SIZE = 32
    MESSAGE_END = "\r\n"


class ReadQueue(object):
    """ A queue that combines incoming packets until a complete one is found.

    This is done by continually adding the result of a `socket.read` call until
    the special byte sequence indicating the end of a packet (protocol-specific)
    is found. This is then added to a queue to be processed.

    NOTE: Because of the way socket reads are handled, this code is definitely
          specific to Python 2.
    """

    def __init__(self):
        self.queue = []
        self.pending = ""

    def read(self, data):
        """ Processes some data into the queue.
        """
        self.pending += data
        index = self.pending.find(protocol.MESSAGE_END)
        if index != -1:
            self.queue.append(self.pending[:index + len(protocol.MESSAGE_END)])
            self.pending = self.pending[index + len(protocol.MESSAGE_END):]
        return True

    @property
    def ready(self):
        """ Returns whether or not the queue is ready to be processed. """
        return len(self.queue) > 0

    def pop(self):
        """ Removes the oldest packet from the queue. """
        return self.queue.pop(0)


class SignalableThread(threading.Thread):
    """ A utility base thread to run a signal function when something happens.
    """

    def __init__(self, on_ready):
        super(SignalableThread, self).__init__()
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

    def __init__(self, pause_length=0):
        super(InfiniteThread, self).__init__()
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
        super(ListenerThread, self).__init__()
        self._on_accept = on_accept
        self.listener = sock

    def _loop_method(self):
        rd, wr, er = select.select([ self.listener ], [], [ self.listener ],
                                   ListenerThread.TIMEOUT)
        if rd:
            client, addr = self.listener.accept()
            print "Accepted peer from", addr
            self._on_accept(addr, client)

        elif er:
            print "An error occurred in the socket."
            self.stop_running()


def extract_id(data):
    """
    >>> extract("stuff|extra|identifier\r\n")
    identifier
    """
    index = utils.find_last(data, '|')
    return float(data[index : -2])


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

    class ResponseHold(object):
        """ Contains info about a particular request (and its response, later).
        """
        def __init__(self, message, event):
            self.sent_message_id = extract_id(message)
            self.sent_message = message
            self.recv_message = None
            self.event = event

        def trigger(self, receiver_socket, message):
            self.recv_socket = receiver_socket
            self.recv_message = message
            self.event.set()

    class SocketEntry(object):
        def __init__(self, request_handler):
            self.handler = request_handler
            self.queue = ReadQueue()
            self.holds = []

        def add_hold(self, message, event):
            self.holds.append(SocketProcessor.ResponseHold(message, event))

    def __init__(self):
        """ Creates a thread instance.

        This manages a set of sockets with particular _generic_ request handler
        functions for each one. These will be called for all messages
        indiscriminantly if there is no handler for a request you sent.
        """
        super(SocketProcessor, self).__init__()

        # dict -> { socket: (request_handler, [ ResponseHold ]) }
        self.sockets = { }

    def add_socket(self, peer_socket, request_handler):
        """ Adds a new socket to manage.

        :peer_socket        A socket object to read from.
        :request_handler    A function that accepts and processes a generic
                            message on the socket.

            This is called when data is received but there is no expecting
            handler. It is called with these args:
                request_handler(socket_received_on, raw_data_received)
        """
        if not isinstance(peer_socket, socket.socket):
            raise TypeError("Initialized processor thread without socket.")

        print "added %s to socket processing list" % repr(peer_socket.getpeername())
        self.sockets[peer_socket] = SocketProcessor.SocketEntry(request_handler)

    def add_response_waiter(self, receiver_socket, message, evt):
        self.sockets[receiver_socket].add_hold(message, evt)

    def _loop_method(self):
        """ Reads the sockets periodically and calls request handlers.
        """
        socket_list = self.sockets.keys()
        if not socket_list: return

        rd, _, er = select.select(socket_list, [], socket_list, 1)
        for sock in rd:
            data = sock.recv(protocol.MIN_MESSAGE_SIZE)
            if not data:
                print "Socket is closed!"
                continue

            print "received raw message from %s: %s" % (
                repr(sock.getpeername()), repr(data))

            entry = self.sockets[sock]
            entry.queue.read(data)
            while entry.queue.ready:
                msg = entry.queue.pop()
                print "Full message received!", repr(msg)

                t = extract_id(msg)
                for response_hold in entry.holds:
                    if response_hold.sent_message_id == t:
                        msg = msg[ : utils.find_last(msg, '|') - 1] + \
                              msg[-len(protocol.MESSAGE_END) : ]
                        response_hold.trigger(sock, msg)
                        break
                else:
                    entry.handler(sock, msg)

    def respond_to(self, request, sock, response):
        message = "%s|%0.3f\r\n" % (response[:-2], extract_id(request))
        return sock.sendall(message)

    @staticmethod
    def request(processor, peer, message, wait_time, on_response):
        """ Initiates a request on a particular thread.

        :processor   the thread instance we're registering with
        :peer        the socket to send the message from
        :message     the message to immediately send on the thread socket
        :wait_time   in seconds, the amount to wait for a response; if this
                     expires, `False` is returned.
        :on_response the callable to run when the response is received.
                        on_response(receiver_socket, response)
        """
        # Temporary: inject unique message send time
        message = "%s|%0.3f\r\n" % (message[:-2], time.time())

        # Create a threading event to be signaled when the response is ready.
        evt = threading.Event()

        # Add the request to the thread's internal request handler list.
        processor.add_response_waiter(peer, message, evt)

        # Send the request and wait for the response.
        print "Sending message from %s to %s: %s" % (
            peer.getsockname(), peer.getpeername(), repr(message))

        peer.sendall(message)
        entry = processor.sockets[peer]
        if not evt.wait(timeout=wait_time):
            return False

        print "Received response for message:", repr(entry.holds[-1].recv_message)

        # TODO: The -1 access is a race condition.
        return on_response(peer, entry.holds[-1].recv_message)
