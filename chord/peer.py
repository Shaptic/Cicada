""" Defines the binding layer between local and remote nodes.

The machine on which the node is running has a `LocalChordNode` instance. All of
its peers are `RemoteChordNode` instances which actually correspond to the
respective `LocalChordNode` instance.

Essentially, communication is established LocalNode's peer list (which is a list
of RemoteNode instances) and another LocalNode's (which is actually running on
the other [remote] machine) peer list.

Here's an detailed outline of the communication involved in joining a Chord
ring, from both local and remote perspectives:

    - Node A becomes a Chord ring, a local node having a listener socket.
    - Node A communicates its listener address to Node B via outside means.
    - Node B connects, using its joiner socket, to Node A's listener.
    - Node B adds the joiner socket to its peer list as RNode A. This
      establishes a link between Node A and B. Similarly, Node A transforms its
      the socket from the listener into a new peer, RNode B, representing Node
      B. Then, the listener socket is available for more connections.
    - Node B: via RNode A, sends JOIN to the peer socket RNode B on Node A.
    - Node A: via RNode B -- JOIN_RESP --> RNode A on Node B.
    - ... time passes ...
    - Node A: RNode B -- UPDATE --> RNode A on Node B.

It's a bit confusing, as is often the case with networks, but you can always
just consider that LocalNode.Peers[index_1], a Remote node, has a socket that is
a direct communication line to another LocalNode.Peers[index_2] socket instance
that exists elsewhere.
"""

import select
import socket
import communication

from . import chordnode
from .message import *


def parse_successor(data):
    index = data.find("NONE")
    if index == -1:
        return data.split(',')
    return "NONE"


class Peer(chordnode.ChordNode):
    """ Represents a remote Chord node in the hash ring.

    The primary purpose of this object is to handle communication from a local
    node to a remote node. It will cache properties within itself, but will
    perform a remote lookup otherwise. It will also listen to changes from the
    node to update the properties.

    For example, accessing `Peer.successor` may (instantly) return a current
    value if it has been fetched or updated recently, but otherwise may require
    actual network communication to fetch it.
    """

    def __init__(self, remote_addr, existing_socket=None):
        """ Establishes a connection to a remote node.

        The address is the receiving end of the socket of the `LocalChordNode`
        that we're connecting to.

        If `existing_socket` exists, there is no connection initiated.
        """
        if not isinstance(remote_addr, tuple) and len(remote_addr) == 2:
            raise TypeError("Must join ring via address pair, got %s!" % (
                remote_addr))

        if existing_socket:
            s = existing_socket
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(remote_addr)

        self.complete = False   # set when the socket closes
        self.remote_addr = remote_addr
        import pdb; pdb.set_trace()
        self.processor = communication.SocketProcessor(s, self.responder)
        self.processor.start()

        super(Peer, self).__init__("%s:%d" % remote_addr)

    def join_ring(self):
        """ Joins a Chord ring by sending a JOIN message.

        The return value is either an error or a message describing the
        successor of this node. The message also implicitly notifies the node
        that we're joining of our existence.
        """

        # This will be done using a proper protocol soon.
        self.pr("Waiting on JOIN response...")
        communication.SocketProcessor.request(self.processor,
            JoinMessage().build_request(), 10, self.responder)

    def responder(self, response):
        if response.build_request() != "JOIN\r\n":
            print "wrong request type. sent"
            print response.sent_message
            print "got"
            print response.recv_message
            raise ValueError("Invalid format! %s" % repr(response.__dict__))

        # The socket will return the successor node corresponding to
        # this node. Thus, we create a new Peer node that represents
        # this successor and return it.
        #
        # The peer is represented just by a remote address, which we
        # parse. If it doesn't exist, we just use the address we used to
        # connect to the ring, instead.
        self.pr("Joiner got response:", response.recv_message)
        join_response = JoinMessage().parse_response(response.recv_message)
        if join_response.succ_addr:     # our homie is the only node!
            addr = self.remote_addr

        # Join the successor.
        print "connected peer is at", join_response.succ_addr
        return Peer(join_response.succ_addr)

    def stabilize(self):
        return

    def fix_fingers(self):
        return

    def notify(self, local_node):
        """ The given `local_node` is notifying this peer of its existence.
        """
        self.peer_sock.sendall("NOTIFY\r\n")
        data = self.peer_sock.recv(64)

    def __str__(self):
        return "<Peer | %s>" % super(Peer, self).__str__()

    def get_predecessor(self):
        # TODO: Set me properly.
        self._pred_expired = False
        if self.predecessor is not None or self._pred_expired:
            return self.predecessor

        # import pdb; pdb.set_trace()
        self.peer_sock.sendall("INFO\r\n")
        data = self.peer_sock.recv(64)
        self.pr("INFO response: %s" % repr(data))

        msg = data[len("INFO-R:"):]
        pred, succ = msg.split('|')
        self.pr("info data: hash=%s,pred=%s,succ=%s" % (repr(pred), repr(succ)))

        pred = pred.split(',')
        succ = succ.split(',')

        return pred
