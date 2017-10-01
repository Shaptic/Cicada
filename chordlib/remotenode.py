""" Defines the binding layer between local and remote peers.

The process on which the peer is running has a `LocalNode` instance. All of its
peers are `RemoteNode` instances which actually correspond to the respective
`LocalNode` instance (which obviously may be on a different process of the same
machine).
"""

import time
import select
import socket

from chordlib  import commlib
from chordlib  import chordnode, L
from chordlib  import peersocket
from chordlib  import routing
from packetlib import chord as chordpkt

class RemoteNode(chordnode.ChordNode):
    """ Represents a remote Chord node in the hash ring.

    This merely contains the ability to establish a connection to another peer,
    as well as hold some remote-specific properties.
    """
    PEER_TIMEOUT = 30

    def __init__(self, on_send, node_hash, listener_addr, existing_socket=None):
        """ Establishes a connection to a remote node.

        The address is the receiving end of the socket of the `LocalNode`
        that we're connecting to.

        If `existing_socket` exists, there is no connection initiated.

        :node_hash              the hash of the remote node.
        :listener_addr          the listener address on the remote node.
        :existing_socket[=None] is there already an established connection?
        """
        if not isinstance(listener_addr, tuple):
            raise TypeError("Must join ring via address pair, got %s!" % (
                            listener_addr))

        if existing_socket is not None:
            s = existing_socket
            if not isinstance(existing_socket, peersocket.PeerSocket):
                raise
        else:
            s = peersocket.PeerSocket(on_send=on_send)
            s.connect(listener_addr)
            L.debug("Socket handle: %d", s.fileno())

        if node_hash is None:   # not set for peer on first join
            h = routing.Hash(value="notset")
        else:
            h = routing.Hash(hashed=node_hash)

        self.peer_sock = s
        self.last_msg = time.time()
        self.timeout = RemoteNode.PEER_TIMEOUT

        super(RemoteNode, self).__init__(h, listener_addr)
        L.info("Created a remote peer with hash %d on %s:%d.",
               self.hash, self.chord_addr[0], self.chord_addr[1])

    def __str__(self):
        if self:
            remote = self.peer_sock.remote
        else:
            remote = ("0", 0)
        return "[%s<-remote@%s:%d(%s)->%s]" % (
            str(int(self.predecessor.hash)) if self.predecessor else None,
            remote[0], remote[1], self.compact,
            str(int(self.successor.hash))   if self.successor   else None)

    @property
    def is_valid(self):
        return self.peer_sock.valid

    @property
    def is_alive(self):
        """ Alive: received a PONG within the last `PEER_TIMEOUT` seconds.
        """
        return self.last_msg + self.timeout >= time.time()
