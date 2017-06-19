""" Defines the binding layer between local and remote nodes.

The machine on which the node is running has a `LocalNode` instance. All of
its peers are `RemoteNode` instances which actually correspond to the
respective `LocalNode` instance.

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
just consider that LocalNode.peers[index_1], a Remote node, has a socket that is
a direct communication line to another LocalNode.peers[index_2] socket instance
that exists elsewhere.
"""

import select
import socket

from   chordlib  import commlib
from   chordlib  import chordnode
from   packetlib import chord
import packetlib.debug


class RemoteNode(chordnode.ChordNode):
    """ Represents a remote Chord node in the hash ring.

    The primary purpose of this object is to handle communication from a local
    node to a remote node. It will cache properties within itself, but will
    perform a remote lookup otherwise. It will also listen to changes from the
    node to update the properties.

    For example, accessing `Peer.successor` may (instantly) return a current
    value if it has been fetched or updated recently, but otherwise may require
    actual network communication to fetch it.
    """

    def __init__(self, remote_addr, peer_listener_addr, existing_socket=None):
        """ Establishes a connection to a remote node.

        The address is the receiving end of the socket of the `LocalNode`
        that we're connecting to.

        If `existing_socket` exists, there is no connection initiated.

        :remote_addr
        :peer_listener_addr
        :existing_socket
        """
        if not isinstance(remote_addr, tuple):
            raise TypeError("Must join ring via address pair, got %s!" % (
                remote_addr))

        if existing_socket is not None:
            s = existing_socket
        else:
            s = commlib.ThreadsafeSocket()
            s.connect(remote_addr)

        self.peer_sock = s
        self.remote_addr = remote_addr
        self.complete = False   # set when the socket closes

        super(RemoteNode, self).__init__(
            "%s:%d" % remote_addr, peer_listener_addr)

    def __str__(self):
        return "<RemoteNode | %s>" % super(RemoteNode, self).__str__()

