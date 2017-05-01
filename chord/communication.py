import threading
import socket
import select
import time


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
        self.queue = [ ]
        self.pending = ""
        self.done = False

    def read(self, sock):
        """ Processes a given socket, returning the socket state.
        """
        data = sock.recv(protocol.MIN_MESSAGE_SIZE)
        if not data:
            self.done = True
            return False

        self.pending += data
        index = self.pending.find(protocol.MESSAGE_END)
        if index != -1:
            self.queue.append(self.pending[:index])
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

    TODO: Add validation that this isn't some arbitrary connection.
    """
    TIMEOUT = 1     # how long should we wait for the socket to be ready?

    def __init__(self, parent, sock):
        super(ListenerThread, self).__init__()
        self.parent = parent
        self.listener = sock

    def _loop_method(self):
        rd, wr, er = select.select([ self.listener ], [], [ self.listener ],
                                   ListenerThread.TIMEOUT)
        if rd:
            client, addr = self.listener.accept()
            print "Accepted peer from", addr
            self.parent.dispatcher.add_peer(client, addr)
            # self.signal()

        elif er:
            print "An error occurred in the socket."
            self.stop_running()

