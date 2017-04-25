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

from . import node

class RemoteChordNode(node.ChordNode):
    """ Represents a remote Chord node in the hash ring.

    The primary purpose of this object is to handle communication from a local
    node to a remote node. It will cache properties within itself, but will
    perform a remote lookup otherwise. It will also listen to changes from the
    node to update the properties.

    For example, accessing `RemoteChord.successor` may (instantly) return a
    current value if it has been fetched or updated recently, but otherwise may
    require actual network communication to fetch it.
    """

    #
    # in LocalChordNode::join_ring(address):
    #   self.joiner.connect(address)
    #   self.peers.append(RemoteChordNode(self.joiner, address))
    #
    # in RemoteChordNode(sock, addr):
    #   self.peer_sock = sock
    #   baseline = self.peer_sock.recv(1024)
    #   self.predecessor = baseline[0]
    #   self.successor = baseline[1]
    #   etc...
    #

    def __init__(self, joiner_sock, remote_addr):
        """ Sends a JOIN request to a peer in an existing ring.

        The address is the receiving end of the socket of the `LocalChordNode`
        that we're connecting to.
        """
        super(RemoteChordNode, self).__init__("")
        if not isinstance(remote_addr, tuple):
            raise TypeError("Must join ring via address pair!")

        self.peer_sock = joiner_sock
        self.remote_addr = remote_addr

        self.peer_sock.sendall("JOIN")
        resp = self.peer_sock.recv(1024)

        succ = homie.fingers.findSuccessor(self.hash)   # our would-be successor
        if succ is None:        # our homie is the only node!
            succ = homie
        self.addNode(succ)      # add successor to our own finger table
        succ.nodeJoined(self)   # notify successor that we joined to them

        assert self.successor == succ, "joinRing: successor not set!"

        return super(RemoteChordNode, self).__init__(homie)

    def nodeJoined(self, homie):
        """ A local node will send a JOIN request to a remote one.

        We need to transmit the request across our socket and await the response
        in order to update internal state.
        """
        pass
