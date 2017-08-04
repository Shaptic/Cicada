""" Defines a local Chord node.

This is the object you want to use to begin structuring a Chord ring on your
machine. At this point, you can either join an existing ring (by using the
`LocalNode.join_ring` method), or simply by waiting for a node to join this
ring.
"""
import collections
import threading
import socket
import select
import random
import time

from chordlib import L  # the logfile
from chordlib import utils as chutils
from chordlib import routing
from chordlib import commlib
from chordlib import chordnode
from chordlib import remotenode

import packetlib
import packetlib.debug
from   packetlib import chord as chordpkt
from   packetlib import utils as pktutils


class LocalNode(chordnode.ChordNode):
    """ Represents the current local node in the Chord hash ring.
    """

    def __init__(self, data, bind_addr):
        """ Creates a node on a specific address with specific data.

        Typically, the data that you pass is simply a string representation of
        the binding address. This is because in Cicada we _use_ the binding
        address hash as the identifier of the node to route packets.

        :data       the data to be hashed by this Chord node. It creates a
                    unique identifier for the node.
        :bind_addr  specifies the address to use for the listener socket.
        """

        # This socket is responsible for inbound connections (from new potential
        # Peer nodes). It is always in an "accept" state in a separate thread.
        self.listener = commlib.ThreadsafeSocket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(bind_addr)
        self.listener.listen(5)

        # This is the listener thread. When it receives a new socket, it will
        # create a Peer object from it.
        L.info("Starting listener thread for %s", self.listener.getsockname())
        self.listen_thread = commlib.ListenerThread(self.listener,
                                                    self.on_new_peer)
        self.listen_thread.start()

        # This is a thread that processes all of the known peers for messages
        # and calls the appropriate message handler.
        self.processor = commlib.SocketProcessor(self.on_error)
        self.processor.start()
        self.data = data

        super(LocalNode, self).__init__(routing.Hash(value=data),
                                        self.listener.getsockname())
        L.info("Created local peer with hash %d on %s:%d.",
               self.hash, self.chord_addr[0], self.chord_addr[1])

        # This thread periodically performs the stabilization algorithm. It is
        # not started until a JOIN request is sent or received.
        self.stable = chordnode.Stabilizer(self)

    def add_peer(self, hash, address, socket=None):
        # First, ensure that this socket doesn't already exist internally.
        if self.predecessor and self.predecessor.hash == hash:
            return self.predecessor

        if self.successor and self.successor.hash == hash:
            return self.successor

        peer = remotenode.RemoteNode(hash, address, socket)
        self.processor.add_socket(peer.peer_sock, self.process)
        return peer

    def join_ring(self, remote, timeout=10):
        """ Joins a Chord ring through a node at the specified address.

        We use the stabilization technique outlined in the Chord paper, which
        means that a JOIN only involves asking our entry point for our immediate
        successor.

        This operation blocks until the response is received or the timeout is
        reached.

        :remote         the address referring to a node in a Chord ring.
        :timeout[=30]   the number of seconds to wait for a response.
        :returns        a 2-tuple of the request and the response (or `False`)
        """
        remote = (socket.gethostbyname(remote[0]), remote[1])
        assert self.predecessor is None, "join_ring: predecessor set!"

        #
        # Create a Peer object that represents the external node that is letting
        # us into the ring. We send a JOIN request to the address, expecting a
        # response indicating our would-be successor.
        #
        # We validate this by establishing a connection to the successor.
        #
        remote_str = "%s:%d" % remote
        L.info("Joining peer ring via %s.", remote_str)
        self.successor = self.add_peer(routing.Hash(value=remote_str), remote)

        request  = chordpkt.JoinRequest.make_packet(self.hash, self.chord_addr)
        response = self.processor.request(self.successor.peer_sock, request,
                                          self.on_join_response, timeout)

        # Temporary until we have a proper higher layer.
        if not response:
            raise ValueError("JOIN request didn't get a response in time.")

        self.stable.start()
        return request, response

    def on_join_request(self, sock, msg):
        """ Receives a JOIN request from a node previously outside the ring.

        Our response is a JOIN containing the would-be successor information of
        the incoming peer. If we're the only ones in the ring, we return our own
        address details and hope they figure out that they're already connected
        to us.
        """
        L.info("Peer (%s:%d) requested to join the network.",
               *sock.getpeername())

        req = chordpkt.JoinRequest.unpack(msg.data)

        # This prevents a loop of connections in a small ring.
        if self.successor is None:
            lookup_successor = self
            self.successor = remotenode.RemoteNode(req.sender, req.listener,
                                                   sock)

        # Look up the successor locally. The successor of the requestor peer
        # belongs in the range (peer.hash, successor.hash].
        #
        # TODO: Look up the successor over the network.
        else:
            ndist = collections.namedtuple("NodeDist", "node dist")
            cmps = [ndist(self, 0), ndist(self.successor, 0)]
            if self.predecessor: cmps.append(ndist(self.successor, 0))

            for idx, i in enumerate(cmps):
                cmps[idx] = i._replace(dist=routing.moddist(int(req.sender),
                                                            int(i.node.hash),
                                                            routing.HASHMOD))

            lookup_successor = min(cmps, key=lambda x: x.dist).node
            L.critical("Successor needs to be looked up in the network.")

        L.info("Allowing connection and responding with our details:")
        L.info("    Our hash: %d", self.hash)
        L.info("    Our successor hash: %d on %s:%d", self.successor.hash,
               *self.successor.chord_addr)
        L.info("    Our predecessor hash: %d on %s",
               0 if not self.predecessor else self.predecessor.hash,
               "n/a" if not self.predecessor else (
                    "%s:%d" % self.predecessor.chord_addr))
        L.info("    Requestee successor hash: %d on %s:%d",
               lookup_successor.hash, *lookup_successor.chord_addr)

        response = chordpkt.JoinResponse.make_packet(lookup_successor, self,
                                                     self.predecessor,
                                                     self.successor,
                                                     original=msg)

        if not self.stable.is_alive():
            self.stable.start()

        self.processor.response(sock, response)
        return response

    def on_join_response(self, sock, msg):
        """ Processes a JOIN response and creates the successor connection.
        """
        response = chordpkt.JoinResponse.unpack(msg.data)

        L.info("We have been permitted to join the network:")
        L.info("    From peer with hash: %d", response.sender.hash)
        L.info("    Sender successor hash: %d on %s:%d",
               response.successor.hash, *response.successor.chord_addr)
        L.info("    Sender predecessor hash: %d on %s",
               0 if not response.predecessor else response.predecessor.hash,
               "n/a" if not response.predecessor else (
                    "%s:%d" % response.predecessor.chord_addr))
        L.info("    Our new successor hash: %d on %s:%d",
               response.req_succ_hash, *response.req_succ_addr)

        # It's possible that the node we used to join the network is also our
        # successor (by chance or if they're alone in the network). In this
        # case, we don't need to do anything.
        if self.successor.chord_addr == response.req_succ_addr:
            L.info("    Our entry peer is actually our successor, too!")

            # We set an invalid hash when we added the peer, so now we need to
            # update it to be accurate.
            self.successor.hash = response.request_successor.hash

        else:
            L.info("    Connecting to our provided successor.")
            self.successor = self.add_peer(response.req_succ_hash,
                                           response.req_succ_addr)

        self.successor.predecessor = response.predecessor
        self.successor.successor = response.successor
        return True

    def on_notify_request(self, sock, msg):
        """ Determine whether or not a node should be our predecessor.
        """
        request = chordpkt.NotifyRequest.unpack(msg.data)
        node = request.sender

        L.info("Received a notification from a (new?) peer.")
        L.info("    Their hash is %d.", node.hash)
        if self.predecessor is not None:
            L.debug("    Testing this in the interval (%d, %d).",
                   int(self.predecessor.hash), int(self.hash))

        set_pred = False
        if self.predecessor is None or \
           routing.Interval(int(self.predecessor.hash),
                            int(self.hash)).within_open(node.hash):
            L.info("    Peer %s is a better predecessor!", node)
            L.info("    Previously it was: %s", self.predecessor)
            self.predecessor = self.add_peer(node.hash, node.chord_addr,
                                             socket=sock)
            self.predecessor.predecessor = node.predecessor
            self.predecessor.successor = node.successor
            set_pred = True

        response = chordpkt.NotifyResponse.make_packet(set_pred, original=msg)
        self.processor.response(sock, response)
        return response

    def on_info_request(self, sock, msg):
        """ Processes an INFO message and responds with our ring details.
        """
        if self.predecessor is None and self.successor is None:
            L.warning("FIXME: Received a request for information, but we aren't"
                      " done processing our join request yet!")
            return

        pred = self.predecessor or self.successor
        succ = self.successor   or pred

        response = chordpkt.InfoResponse.make_packet(self, pred, succ,
                                                     original=msg)

        L.info("Peer (%s:%d) requested info about us.", *sock.getpeername())
        L.info("Our details:")
        L.info("    Hash: %d", self.hash)
        L.info("    Predecessor: %s", pred)
        L.info("    Successor:   %s", succ)

        self.processor.response(sock, response)
        return True

    def on_info_response(self, sock, msg):
        """ Processes a peer's information from an INFO response.
        """
        response = chordpkt.InfoResponse.unpack(msg.data)
        if self.successor.peer_sock   != sock and \
           self.predecessor.peer_sock != sock:
            L.warning("Unknown socket source? %s:%d" % sock.getpeername())

        if self.successor.hash == response.sender.hash:
            node = self.successor

        elif self.predecessor and self.predecessor.hash == response.sender.hash:
            node = self.predecessor

        else:
            node = remotenode.RemoteNode(response.sender.hash,
                                         response.sender.chord_addr,
                                         existing_socket=sock)

        L.info("Received info from a peer: %d", response.sender.hash)
        L.info("    Successor hash: %d on %s:%d", response.successor.hash,
               *response.successor.chord_addr)
        L.info("    Predecessor hash: %d on %s:%d", response.predecessor.hash,
               *response.predecessor.chord_addr)

        node.predecessor = response.predecessor
        node.successor = response.successor
        return node

    def on_error(self, closed_sock, graceful):
        """ Removes a peer from internal structures.
        """
        remote = closed_sock.getpeername()
        L.warning("Neighbor (%s:%d) went down %sgracefully",
                  remote[0], remote[1], "" if graceful else "un")
        L.critical("Not fully implemented.")

        if self.successor and self.successor.peer_sock == closed_sock:
            L.critical("Lost our successor! (we were %s)", self)
            self.successor = None

        if self.predecessor and self.predecessor.peer_sock == closed_sock:
            self.predecessor = None

    def on_new_peer(self, address, sock):
        """ Adds a newly connected peer to the internal socket processor.
        """
        L.debug("New peer from %s:%d (on %s:%d)", address[0], address[1],
                *sock.getpeername())
        self.processor.add_socket(sock, self.process)

    def stabilize(self):
        """ Runs the stabilization algorithm.

        Stabilizing means asking our successor, n, "for the successor's
        predecessor p, and decid[ing] whether p should be [our] successor
        instead." Then, we tell n's successor about n. That way, the successor
        can learn about n if it didn't already know in the first place.
        """
        if self.successor is None:  # nothing to stabilize yet
            return

        # Query the successor for information.
        L.info("Asking our successor (%s) for neighbor info...", self.successor)
        request = chordpkt.InfoRequest.make_packet()
        response = self.processor.request(self.successor.peer_sock,
                                          request, self.on_info_response,
                                          wait_time=2)
        if not response:
            L.error("on_info_response failed.")
            return

        # It's possible that the successor hasn't stabilized yet, and thus
        # also doesn't have a predecessor node.
        x = self.successor.predecessor or self

        # We HAVE to use an open-ended range check, because if our successor's
        # predecessor is us (as it would be in the normal case), we'd be setting
        # us as our own successor!
        if routing.Interval(int(self.hash),
                            int(self.successor.hash)).within_open(int(x.hash)):
            L.info("Our successor's predecessor is closer to us than our "
                   "current successor!")
            L.info("    Specifically, successor.predecessor: %d", x.hash)
            L.info("    Whereas self.successor: %d", x.hash)
            L.info("    And self.range: [%d, %d)",
                   int(self.hash), int(self.successor.hash))

            # We can't close the successor socket here, because it might be also
            # used for our predecessor socket (2-node network growing). Suppose
            # we have:
            #
            #   - At first, A --> B --> A.
            #   - Then, after C joins, A --> B --> C --> A.
            #   - We still need the connection between A <--> B, because B is
            #     A's successor, despite not being our successor anymore.
            #
            sp = self.successor.predecessor
            self.successor = self.add_peer(sp.hash, sp.chord_addr)

        # We need to notify our successor about ourselves (regardless of whether
        # we adjusted or not), so they can set their predecessor appropriately.
        L.info("Notifying our successor (%s) about us.", self.successor)
        request = chordpkt.NotifyRequest.make_packet(self, self.predecessor,
                                                     self.successor)
        self.processor.request(self.successor.peer_sock, request,
                               lambda *args: True, wait_time=0)
                               # fire & forget

    def process(self, peer_socket, msg):
        L.debug("Received message %s from %s:%d", repr(msg),
            *peer_socket.getsockname())

        handlers = {
            packetlib.MessageType.MSG_CH_JOIN:      self.on_join_request,
            packetlib.MessageType.MSG_CH_INFO:      self.on_info_request,
            packetlib.MessageType.MSG_CH_NOTIFY:    self.on_notify_request,
            # packetlib.MessageType.MSG_CH_LOOKUP:    self.on_lookup_request,
        }

        for msg_type, func in handlers.iteritems():
            if msg.type == msg_type:
                func(peer_socket, msg)
                break
        else:
            raise ValueError("Message received (type=%s) without handler." % (
                message.MessageType.LOOKUP[msg.type]))

    def _peerlist_contains(self, elem):
        if isinstance(elem, tuple):
            for peer in self.peers:
                if peer.chord_addr == elem:
                    return peer

        elif isinstance(elem, commlib.ThreadsafeSocket):
            for peer in self.peers:
                if peer.peer_sock == elem:
                    return peer
            else:
                return self._peerlist_contains(elem.getsockname())

        elif isinstance(elem, remotenode.RemoteNode):
            for peer in self.peers:
                if peer == elem:
                    return peer
            else:
                return self._peerlist_contains(elem.peer_sock)

    @property
    def predecessor(self):
        return self._predecessor

    @property
    def successor(self):
        return self._successor

    @predecessor.setter
    def predecessor(self, pred):
        if self._predecessor and self._predecessor != self._successor:
            self.processor.close_socket(self._predecessor.peer_sock)
        self._predecessor = pred

    @successor.setter
    def successor(self, succ):
        if self._successor and self._successor != self._predecessor:
            self.processor.close_socket(self.successor.peer_sock)
        self._successor = succ

    def __str__(self):
        return "[%s<-local(%s:%d|hash=%d)->%s]" % (
            str(int(self.predecessor.hash)) if self.predecessor else None,
            self.chord_addr[0], self.chord_addr[1], self.hash,
            str(int(self.successor.hash))   if self.successor   else None)
