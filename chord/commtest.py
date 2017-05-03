""" A test for the multi-threaded, multi-socket handler interface.
"""

from   socket import *
import time
import threading
import communication as comms

# Create a socket to accept a JOIN request.
starter = socket(AF_INET, SOCK_STREAM)
starter.bind(('localhost', 5000))
starter.listen(2)

print "Server socket created, on", starter.getsockname()
starter_event = threading.Event()

def on_starter_accept(peer_address, peer_socket):
    """ Signals that the socket has received a connection.

    We register a handler to respond to a JOIN message with a JOIN-R message.
    Then, we notify the waiting event.
    """
    def on_join_request(receiver_socket, raw_request):
        print "server received", repr(raw_request), \
              "from", receiver_socket.getsockname()
        receiver_socket.sendall("JOIN-R|%0.3f\r\n" % float(
            comms.extract_id(raw_request)))

    print "Creating server peer thread from", peer_socket.getpeername()
    processor = comms.SocketProcessor()
    processor.add_socket(peer_socket, on_join_request)
    processor.start()

    print "Signaling client that they should be ready to receive."
    starter_event.set()

# Creates a thread to listen on the socket until it receives a JOIN request.
# When it does, it will trigger the handler.
listener = comms.ListenerThread(starter, on_starter_accept)
listener.start()

# Connect a socket to the listener.
joiner = socket(AF_INET, SOCK_STREAM)
joiner.connect(('localhost', 5000))
print "Client socket created, on '%s'" % repr(joiner.getpeername())

# Wait until the listener thread receives it.
starter_event.wait()
print "Client accepted, sending JOIN."

def on_join_response(receiver_socket, response):
    """ Handles the response to a JOIN request.
    """
    return response

# Send a JOIN request to the listener.
peer = comms.SocketProcessor()

print "Starting client processing thread."
peer.start()
peer.add_socket(joiner, on_join_response)

print "Added joiner socket and sending %s" % (repr("JOIN\r\n"))
on_join_response_retval = comms.SocketProcessor.request(
    peer, joiner, "JOIN\r\n", None, on_join_response)

print "JOIN return value: %s" % repr(on_join_response_retval)
