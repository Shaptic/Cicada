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

# Simulation:
#   chord_addr = ('192.168.0.101', 2016)
#   local_peer = LocalChordNode(host_addr)
#   local_peer.joiner.connect(chord_addr)
#   chord_succcesor = local_peer.joiner.recv(1024)

import select
from . import chordnode

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

    def __init__(self, joiner_sock, remote_addr):
        """ Sends a JOIN request to a peer in an existing ring.

        The address is the receiving end of the socket of the `LocalChordNode`
        that we're connecting to.
        """
        if not isinstance(remote_addr, tuple) and len(remote_addr) == 2:
            raise TypeError("Must join ring via address pair, got %s!" % (
                remote_addr))

        self.peer_sock = joiner_sock
        self.remote_addr = remote_addr
        self.complete = False   # set when the socket closes

        super(Peer, self).__init__("%s:%d" % remote_addr)

    def join_ring(self):
        """ Joins a Chord ring by sending a JOIN message.

        The return value is either an error or a message describing the
        successor of this node. The message also implicitly notifies the node
        that we're joining of our existence.
        """

        # This will be done using a proper protocol soon.
        self.pr("Waiting on JOIN response...")
        self.peer_sock.connect(self.remote_addr)
        self.peer_sock.sendall("JOIN\r\n")
        read_list, _, _ = select.select([ self.peer_sock ], [ ], [ ], 5)
        if read_list:
            resp = read_list[0].recv(1024)
            self.pr("Joiner got response:", resp)

            if resp.startswith("JOIN-R:"):
                # The socket will return the successor node corresponding to
                # this node. Thus, we create a new Peer node that represents
                # this successor and return it.
                #
                # The peer is represented just by a remote address, which we
                # parse. If it doesn't exist, we just use the address we used to
                # connect to the ring, instead.
                addr = parse_successor(resp)
                if addr == "NONE":  # our homie is the only node!
                    addr = self.remote_addr

                print "connected peer is at", addr
                return Peer(self.peer_sock, addr)

            raise ValueError("Invalid format! %s" % repr(resp))

        else:
            raise ValueError("Timed out waiting for listener response!")

    def stabilize(self):
        return

    def fix_fingers(self):
        return

    def notify(self, local_node):
        """ Notifies the remote Peer this object represents about the node.
        """
        pass

    def __str__(self):
        return "<Peer | %s>" % super(Peer, self).__str__()

    def get_predecessor(self):
        # TODO: Set me properly.
        self._pred_expired = False
        if self.predecessor is not None or self._pred_expired:
            return self.predecessor

        self.peer_sock.sendall("INFO")
        data = self.peer_sock.recv(32)
        print "INFO response:", data
        msg = data[len("INFO-R:"):]
        pred, succ = msg.split('|')
        print "info data: pred=%s,succ=%s" % (pred, succ)

        pred = pred.split(',')
        succ = succ.split(',')

        self.predecessor = pred
        self.successor = succ

