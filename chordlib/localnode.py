""" Defines a local Chord node.

This object begins structuring a Chord network on your machine. At this point,
you can either join an existing ring (by using the `LocalNode.join_ring`
method), or simply by waiting for a peer to join this ring.
"""

import collections
import threading
import functools
import logging
import socket
import select
import random
import time

from chordlib import L  # the logfile
from chordlib import utils as chutils
from chordlib import routing
from chordlib import commlib
from chordlib import heartbeat
from chordlib import chordnode
from chordlib import remotenode

import chordlib
import packetlib
import packetlib.debug
from   packetlib import message
from   packetlib import chord as chordpkt
from   packetlib import utils as pktutils


class LocalNode(chordnode.ChordNode):
    """ Represents the current local peer in the Chord network.

    Connection Design
    =================
    At the core, there's a `SocketProcessor` object that runs in a separate
    thread asynchronously processing all of the established connections. This is
    at a minimum two connections to the direct neighbors, and at a maximum
    `log(n) + 1` connections, where `n` is the size of the hash ring.

    These raw sockets are linked to peers in this object in a list. Every node
    maintains direct properties that link to its predecessor and successor, but
    other connections (such as a when _another_ peer considers us as its
    successor) are only in the peer list.

    Thus, when a predecessor is replaced by the NOTIFY flow, we maintain the old
    connection for the other peer's sake, but no longer directly in the
    `predecessor` property. Likewise for successors. When the old predecessor
    decides that it's time to drop the connection (because they now know about
    the better successor peer), we remove it from our internal list as well.

    The predecessor is ONLY set during stabilization, in which, after another
    peer, B, decides to make this peer, A, its successor, notifies A and B
    decides that this is truly a better predecessor.

    Similarly, the ONLY time that the successor is set is on a NOTIFY request in
    which the sender's (S) predecessor is better than the current peer's (P).
    The peer will respond with a bit indicating whether or not the new successor
    was "accepted," which establishes that it's now a one-way relationship
    between peer S -> P.

    TODO: Introduce some kind of notification system so that the neighboring
          peer can immediately know to requery for the new successor, rather
          than waiting for the arbitrary stabilization routine.
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
        self.processor = commlib.SocketProcessor(self.on_shutdown,
                                                 self.on_error)
        self.processor.start()
        self.peers = chutils.LockedSet()
        self.data = data
        self.on_remove = lambda *args: None

        super(LocalNode, self).__init__(routing.Hash(value=data),
                                        self.listener.getsockname())
        L.info("Created local peer with hash %d on %s:%d.",
               self.hash, self.chord_addr[0], self.chord_addr[1])

        # This thread periodically purges the peerlist of dead peers that
        # haven't responded to our PINGs.
        self.heartbeat = heartbeat.HeartbeatManager(self.peers, self)

        # This thread periodically performs the stabilization algorithm. It is
        # not started until a JOIN request is sent or received.
        self.stable = chordnode.Stabilizer(self)

    def create_peer(self, hash, address, socket=None):
        """ Create a new peer if necessary.

        :hash           `Hash` instance of the new peer
        :address        2-tuple of the listener address of the new peer
        :socket[=None]  optional socket of an existing connection for the peer

        :returns        a new peer if one matching (any of) the criteria didn't
                        find an existing peer
        """
        for criteria in (hash, address, socket):
            node = self._peerlist_contains(hash)
            if node: return node

        peer = remotenode.RemoteNode(hash, address, existing_socket=socket)
        self.processor.add_socket(peer.peer_sock, self.process)
        self.peers.add(peer)
        return peer

    def remove_peer(self, peer):
        """ Shuts down a peer connection and removes it.
        """
        if not self._peerlist_contains(peer):
            L.error("Tried removing a peer that doesn't exist?")
            return False

        self.on_remove(self, peer)
        self.processor.shutdown_socket(peer.peer_sock)
        self.peers.remove(peer)
        return True

    def join_ring(self, remote, timeout=10):
        """ Joins a network through a peer at the specified address.

        This operation blocks until the response is received or the timeout is
        reached.

        :remote         the address referring to a peer in a Chord ring.
        :timeout[=30]   the number of seconds to wait for a response.
        :returns        a 2-tuple of the request and the response (or `False`).
        """
        remote = (socket.gethostbyname(remote[0]), remote[1])
        assert self.predecessor is None, "join_ring: predecessor set!"

        #
        # Create a Peer object that represents the external peer that is letting
        # us into the ring. We use a fake hash value for the peer that we'll
        # fill in later. We send a JOIN request to the address, expecting a
        # response indicating our would-be successor.
        #
        # We validate this by establishing a connection to the successor.
        #
        remote_str = "%s:%d" % remote
        L.info("Joining peer ring via %s.", remote_str)
        self.successor = self.create_peer(routing.Hash(value=remote_str),
                                          remote)

        print "Set initial hash (pre-join): ", int(self.successor.hash)

        request  = chordpkt.JoinRequest.make_packet(self.hash, self.chord_addr)
        response = self.processor.request(self.successor.peer_sock, request,
                                          self.on_join_response, timeout)

        # Temporary until we have a proper higher layer.
        if not response:
            raise ValueError("JOIN request didn't get a response in time.")

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

        # We were alone, and now we have a friend.
        if self.successor is None:
            lookup_successor = self
            self.successor = self.create_peer(req.sender, req.listener,
                                              socket=sock)

        # Look up the successor locally. The successor of the requestor peer
        # belongs in the range (peer.hash, successor.hash].
        #
        # TODO: Look up the successor over the network. Or do we just refer to
        #       the finger table and let the node optimize itself?
        else:
            L.critical("Successor needs to be looked up in the network.")
            ndist = collections.namedtuple("NodeDist", "node dist")
            cmps = [ndist(self, 0), ndist(self.successor, 0)]
            if self.predecessor: cmps.append(ndist(self.successor, 0))

            for idx, i in enumerate(cmps):
                cmps[idx] = i._replace(dist=routing.moddist(int(req.sender),
                                                            int(i.node.hash),
                                                            routing.HASHMOD))

            lookup_successor = min(cmps, key=lambda x: x.dist).node

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
            self.heartbeat.start()

        self.processor.response(sock, response)
        return response

    def on_join_response(self, sock, msg):
        """ Processes a JOIN response and creates the successor connection.
        """
        if msg is None: return False    # socket went down prior
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
        # case, we don't need to do anything except update the fake hash value
        # we initially set (since we could only estimate what the hash could
        # have been of this peer).
        if self.successor.chord_addr == response.req_succ_addr:
            L.info("    Our entry peer is actually our successor, too!")
            self.successor.hash = response.request_successor.hash
            print "Updated hash (post-join):", int(self.successor.hash)

        else:
            # From this point forward, successor _must always_ be valid.
            L.info("    Connecting to our provided successor.")
            self.successor = self.create_peer(response.request_successor.hash,
                                              response.req_succ_addr)

        self.successor.predecessor = response.predecessor
        self.successor.successor = response.successor
        self.stable.start()
        self.heartbeat.start()
        return True

    def on_notify_request(self, sock, msg):
        """ Determine whether or not a node should be our predecessor.
        """
        request = chordpkt.NotifyRequest.unpack(msg.data)
        node = request.sender

        L.info("Received a notification from a peer (hash=%d).", node.hash)
        if self.predecessor is not None:
            L.debug("    Testing this in the interval (%d, %d).",
                   int(self.predecessor.hash), int(self.hash))

        set_pred = False
        if self.predecessor is None or \
           routing.Interval(int(self.predecessor.hash),
                            int(self.hash)).within_open(node.hash):
            L.info("    Peer %s is a better predecessor!", node)
            L.info("    Previously it was: %s", self.predecessor)

            self.predecessor = self.create_peer(node.hash, node.chord_addr,
                                                socket=sock)
            self.predecessor.predecessor = node.predecessor
            self.predecessor.successor = node.successor
            set_pred = True

        response = chordpkt.NotifyResponse.make_packet(set_pred, original=msg)
        self.processor.response(sock, response)
        return response

    def on_notify_response(self, sock, msg):
        response = chordpkt.NotifyResponse.unpack(msg.data)
        node = self._peerlist_contains(sock)
        if not node: return False
        return True

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
        L.info("Our details (%s:%d):", *self.chord_addr)
        L.info("    Hash: %d", self.hash)
        L.info("    Predecessor: %s", pred)
        L.info("    Successor:   %s", succ)

        self.processor.response(sock, response)
        return True

    def on_info_response(self, sock, msg):
        """ Processes a peer's information from an INFO response.
        """
        if msg is None:
            L.warning("INFO request failed to get response because the "
                      "socket went down.")
            return False    # socket went down prior

        response = chordpkt.InfoResponse.unpack(msg.data)
        node = self._peerlist_contains(sock)
        if not node:
            L.warning("Unknown socket source? %s:%d" % sock.getpeername())
            node = self.create_peer(response.sender.hash,
                                    response.sender.chord_addr, socket=sock)

        L.info("Received info from a peer: %s", response.sender)
        L.info("    Successor on: %s:%d",   *response.successor.chord_addr)
        L.info("    Predecessor on: %s:%d", *response.predecessor.chord_addr)

        node.predecessor = response.predecessor
        node.successor = response.successor
        return node

    def lookup(self, address=None, hash=None, timeout=10):
        if address == hash:
            raise ValueError("expected one of: address, hash; got both/none")

        if address is not None and \
           not isinstance(address, tuple) or len(address) != 2 or \
           not isinstance(address[1], int):
            raise ValueError("expected addr=(host, port), got %s" % address)

        if hash is not None and \
           not isinstance(hash, routing.Hash):
            raise ValueError("expected hash=Hash, got %s" % type(hash))

        if address: hash = routing.Hash(value="%s:%d" % address)
        request = chordpkt.LookupRequest.make_packet(self.hash, hash)
        response = self.processor.request(self.succesor, request,
                                          self.on_lookup_response,
                                          wait_time=timeout)

        L.info("Lookup for %s resulted in: %s", address or hash, response)
        L.info("  Lookup result listening on: %s:%d", *response.listener)
        return response

    def on_lookup_request(self, sock, msg):
        """ Forwards to next closest node or looks up request.
        """
        request = chordpkt.LookupRequest.unpack(msg.data)
        if request.lookup == self.hash:
            response = chordpkt.LookupResponse.make_packet(self.hash,
                                                           request.lookup,
                                                           self.hash,
                                                           self.chord_addr)
            self.processor.response(sock, response)

        # Forward to the next closest node.
        else:
            def respond(original, responder, reply):
                response = chordpkt.LookupResponse.unpack(reply.data)
                response = chordpkt.LookupResponse.make_packet(self.hash,
                    response.lookup, response.mapped, response.listener,
                    hops=response.hops + 1) # change sender, increment hop count

                self.processor.response(original, response)

            distances = []
            PeerDist = collections.namedtuple("PeerDist", "peer dist")
            for peer in self.peers:
                dist = routing.moddist(int(request.lookup), int(peer.hash),
                                       routing.HASHMOD)
                distances.append(PeerDist(peer, dist))

            nearest = min(distances, key=lambda x: x.dist)
            self.processor.request(nearest.peer, request,
                                   functools.partial(respond, sock),
                                   wait_time=0)

    def on_lookup_response(self, sock, msg):
        return chordpkt.LookupResponse.unpack(msg.data)

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
        try:
            response = self.processor.request(self.successor.peer_sock,
                                              request, self.on_info_response,
                                              wait_time=2)
            if not response:
                L.error("on_info_response failed.")
                return

        except ValueError:
            L.warning("The successor socket went down during stabilization.")
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
            L.info("    And self.range: [%d, %d)", self.hash,
                   self.successor.hash)

            # We can't always close the successor socket here, because it might
            # be also used for our predecessor socket (in a 3-node ring).
            # Suppose we have:
            #
            #   - At first, A --> B --> A.
            #   - Then, after C joins, A --> B --> C --> A.
            #   - We still need the connection between A <--> B, because B is
            #     A's successor, despite not being our successor anymore.
            sp = self.successor.predecessor
            self.successor = self.create_peer(sp.hash, sp.chord_addr)

        # We need to notify our successor about ourselves (regardless of whether
        # we adjusted or not), so they can set their predecessor appropriately.
        L.info("Notifying our successor (%s) about us.", self.successor)
        request = chordpkt.NotifyRequest.make_packet(self, self.predecessor,
                                                     self.successor)
        self.processor.request(self.successor.peer_sock, request,
                               None, wait_time=0)

    def process(self, peer_socket, msg):
        L.debug("Received message %s from %s:%d", repr(msg),
            *peer_socket.getsockname())

        handlers = {
            packetlib.MessageType.MSG_CH_JOIN:      (self.on_join_request,   0),
            packetlib.MessageType.MSG_CH_INFO:      (self.on_info_request,   0),
            packetlib.MessageType.MSG_CH_NOTIFY:    (self.on_notify_request, 0),
            packetlib.MessageType.MSG_CH_LOOKUP:    (self.on_lookup_request, 0),
            packetlib.MessageType.MSG_CH_PING:      (self.heartbeat.on_ping, 0),
        }

        for msg_type, params in handlers.iteritems():
            func, response = params
            if msg.type == msg_type and response == msg.is_response:
                func(peer_socket, msg)
                break
        else:
            L.error("Message received (type=%s) without handler.",
                    message.MessageType.LOOKUP[msg.type])
            msg.dump()

    def _peerlist_contains(self, elem):
        """ Returns a peer object associated with a property.

        Valid properties are: hashes, listener addresses, sockets, or existing
        peer objects.
        """
        if isinstance(elem, tuple):
            for peer in self.peers:
                if peer.chord_addr == elem:
                    return peer

        elif isinstance(elem, routing.Hash):
            for peer in self.peers:
                if peer.hash == elem:
                    return peer

        elif isinstance(elem, commlib.ThreadsafeSocket):
            for peer in self.peers:
                if peer.peer_sock == elem:
                    return peer
            return self._peerlist_contains(elem.getsockname())

        elif isinstance(elem, chordnode.ChordNode):
            for peer in self.peers:
                if peer == elem:
                    return peer
            return self._peerlist_contains(elem.peer_sock)

        return None

    def on_shutdown(self, socket):
        """ A peer shut down cleanly, so remove it from processing.
        """
        return self.on_error(socket, graceful=True)

    def on_error(self, socket, graceful=False):
        """ On associating a socket with a peer, removes it from the peerlist.
        """

        # Intentionally don't use `_peerlist_contains` to avoid any calls on the
        # socket object that may throw.
        node = None
        for peer in self.peers:
            if peer.peer_sock == socket:
                node = peer
                break

        if node:
            remote = node.chord_addr
            L.warning("Neighbor (%s:%d) went down %sgracefully", remote[0],
                      remote[1], "" if graceful else "un-")
        else:
            L.warning("An unknown neighbor went down %sgracefully.",
                      "" if graceful else "un-")
            return

        #
        # TODO: Successor lists for backup successors and routing tables for
        #       predecessor lookups!
        #
        self.on_remove(self, node)

        if self.successor and node == self.successor:
            print "Lost our successor! (we are %s)" % self
            L.critical("Lost our successor! (we are %s)", self)
            self.successor = None

        if self.predecessor and node == self.predecessor:
            print "Lost our predecessor! (we are %s)" % self
            L.critical("Lost our predecessor! (we are %s)", self)
            self.predecessor = None

        self.peers.remove(node)

    def on_new_peer(self, address, sock):
        """ Adds a newly connected peer to the internal socket processor.
        """
        L.debug("New peer from %s:%d", *address)
        self.processor.add_socket(sock, self.process)

    def __str__(self):
        return "[%s<-local(%s|peers=%d)->%s]" % (
            str(int(self.predecessor.hash)) if self.predecessor else None,
            self.compact, len(self.peers),
            str(int(self.successor.hash))   if self.successor   else None)
