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


def handle_failed_request(fn):
    """ Protects against cancelled requests.

    If peer shuts down with pending requests, the handler is called with a
    `None` message. Here, we validate against that, returning `False` if needed.
    """
    def wrapper(self, sock, msg):
        if msg is None:
            L.warning("INFO request failed to get response because the "
                      "socket went down.")
            return False    # socket went down prior
        return fn(self, sock, msg)
    return wrapper


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

    def __init__(self, data, bind_addr, on_send=lambda *args: None):
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
        self.listener = commlib.ThreadsafeSocket(on_send)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(bind_addr)
        self.listener.listen(5)

        # This is the listener thread. When it receives a new socket, it will
        # create a Peer object from it.
        L.info("Starting listener thread for %s", self.listener.getsockname())
        self.listen_thread = commlib.ListenerThread(self.listener,
                                                    self.on_new_peer)
        self.listen_thread.start()

        self.peers = chutils.LockedSet()
        self.data = data
        self.on_remove = lambda *args: None
        self.on_send = on_send
        # self.on_recv = on_message_handler

        super(LocalNode, self).__init__(routing.Hash(value=data),
                                        self.listener.getsockname())
        L.info("Created local peer with hash %d on %s:%d.",
               self.hash, self.chord_addr[0], self.chord_addr[1])

        # This is a thread that processes all of the known peers for messages
        # and calls the appropriate message handler.
        self.processor = commlib.SocketProcessor(self,
                                                 self.on_shutdown,
                                                 self.on_error)
        self.processor.start()

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

        peer = remotenode.RemoteNode(self.on_send, hash, address,
                                     existing_socket=socket)
        self.processor.add_socket(peer.peer_sock, self.process)
        self.peers.add(peer)
        return peer

    def remove_peer(self, peer):
        """ Shuts down a peer connection and removes it.
        """
        if not self._peerlist_contains(peer):
            L.error("Tried removing a peer that doesn't exist?")
            return False

        try:
            self.on_remove(self, peer)
            self.processor.shutdown_socket(peer.peer_sock)
            self.peers.remove(peer)

        except Exception:
            L.warning("Failed to remove a peer? %s" % peer)

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

        request  = chordpkt.JoinRequest.make_packet(self.hash, self.chord_addr)
        response = self.processor.request(self.successor.peer_sock, request,
                                          self.on_join_response, timeout)

        # Temporary until we have a proper higher layer.
        if not response:
            raise ValueError("JOIN request didn't get a response in time.")

        return request, response

    def leave_ring(self):
        for peer in self.peers.lockfree_iter():
            self.processor.shutdown_socket(peer.peer_sock)

        self.peers = chutils.LockedSet()
        self.stable.stop_running()
        self.heartbeat.stop_running()
        self.stable.join(1000)
        self.heartbeat.join()

        self.predecessor = None
        self.successor = None

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

        L.info("Allowing connection and responding with our details:")
        L.info("    We are: %s", self)
        L.info("    Our predecessor: %s", self.predecessor)
        L.info("    Our successor: %s", self.successor)
        L.info("    The peer's hash is: %d", req.sender)

        # We were alone, and now we have a friend.
        if self.successor is None:
            self.successor = self.create_peer(req.sender, req.listener,
                                              socket=sock)
            response = chordpkt.JoinResponse.make_packet(self, self,
                                                         self.predecessor,
                                                         self.successor,
                                                         original=msg)
            self.processor.response(sock, response)
            retval = response

        # Look up the successor locally. The successor of the requestor peer
        # belongs in the range (peer.hash, successor.hash].
        else:
            def handler(sock, orig, result, msg):
                response = chordpkt.JoinResponse.make_packet(result, self,
                                                             self.predecessor,
                                                             self.successor,
                                                             original=orig)
                self.processor.response(sock, response)

            L.info("We need to make a remote lookup to make a good "
                   "successor recommendation.")

            handler(sock, msg,
                    self._find_closest_peer_moddist(req.sender),
                    None)
            return True

            peer = self._peerlist_contains(sock)
            self.lookup(req.sender, functools.partial(handler, sock, msg), 0,
                        requestor=peer)
            retval = True

        if not self.stable.is_alive():
            self.stable.start()
            self.heartbeat.start()
        return retval

    @handle_failed_request
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

        # Update the fake hash value we initially set (since we could only
        # estimate what the hash could have been of this peer).
        self.successor.hash = response.sender.hash

        # It's possible that the node we used to join the network is also our
        # successor (by chance or if they're alone in the network). In this
        # case, we don't need to do anything.
        if self.successor.chord_addr == response.req_succ_addr:
            L.info("    Our entry peer is actually our successor, too!")

        else:
            # From this point forward, successor _must always_ be valid.
            L.info("    Connecting to our provided successor.")
            self.successor = self.create_peer(response.request_successor.hash,
                                              response.req_succ_addr)

        self.successor.predecessor = response.predecessor
        self.successor.successor = response.successor

        if not self.stable.is_alive():
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

    @handle_failed_request
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

    @handle_failed_request
    def on_info_response(self, sock, msg):
        """ Updates (or creates) a peer with up-to-date properties.
        """
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

    def on_lookup_request(self, sock, msg):
        """ Forwards to next closest node or looks up request.
        """
        peer = self._peerlist_contains(sock)
        req = chordpkt.LookupRequest.unpack(msg.data)

        def on_response(socket, request, value, result, response):
            """ A specialized handler to route the lookup response packet.
            """
            if response is None:
                L.warning("Failed to receive a response for our lookup.")
                L.info("Using ourselves as the response.")
                response = chordpkt.LookupResponse.make_packet(
                    self.hash, value, self.hash, self.chord_addr,
                    original=request)
                self.processor.response(socket, response)
                return

            response = chordpkt.LookupResponse.unpack(response.data)
            duplicate = chordpkt.LookupResponse.make_packet(
                self.hash, response.lookup, response.mapped, response.listener,
                hops=response.hops + 1, original=request)

            L.info("Received a response for our forwarded lookup request.")
            L.info("  The resulting peer: %d on %s:%d", duplicate.lookup,
                   *duplicate.mapped)
            self.processor.response(socket, duplicate)

        L.info("Received a lookup request from peer: %d", req.sender)
        self.lookup(req.lookup,
                    functools.partial(on_response, sock, msg, req.lookup), 0,
                    requestor=peer)

    def lookup(self, value, on_response, timeout, requestor=None):
        """ Performs an asynchronous LOOKUP request on a certain value.

        :value          a `Hash` value that we're looking up
        :on_response    an asynchronously-called handler that will process
                        the lookup result (if any), in the format:
                            on_response(Peer, message)
            where the `Peer` is the value that corresponds to the peer that is
            responsible for the lookup value, and the `message` is the raw
            `MessageContainer` object corresponding to the response we received
            resolving this peer. If the response was resolved locally, this is
            set to `None`.
        :timeout        in seconds, the amount of time to wait for the response
        """
        def on_lookup_response(secondary_handler, response_socket,
                               response_message):
            """ The internal wrapper handler for processing a LOOKUP response.
            """
            if response_message is None:
                secondary_handler(None, None)
                return False

            r = chordpkt.LookupResponse.unpack(response_message.data)

            L.info("  Got a response for the lookup value %d.", r.lookup)
            L.info("  The responder was: %d", r.sender)
            L.info("  The lookup result: %d on %s:%d", r.mapped, *r.listener)
            L.debug("    took %d hops.", r.hops)

            result = chordnode.ChordNode(r.mapped, r.listener)
            secondary_handler(result, r)
            return True

        L.info("Peer %s is looking up the value %d.", self, value)

        # First, is this our responsibility?
        pred = self.predecessor or self.successor
        iv = routing.Interval(int(pred.hash), int(self.hash), routing.HASHMOD)
        if iv.within_open(int(value)) or value == self.hash:
            L.info("  %d falls into our interval, (%d, %d].", value,
                   pred.hash, self.hash)
            return on_response(self, None)

        # If it's not us, find the closest hop we know of.
        # exclusion = set((requestor,)) if requestor else set()
        # nearest = self._find_closest_peer(value, exclude=exclusion)
        nearest = self.successor

        L.info("  Forwarding lookup to the nearest neighbor we're aware of:")
        L.info("    Nearest neighbor: %s", nearest)

        request = chordpkt.LookupRequest.make_packet(self.hash, value)
        self.processor.request(nearest.peer_sock, request,
                               functools.partial(on_lookup_response,
                                                 on_response),
                               wait_time=timeout)

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

        except ValueError, e:
            L.warning("The successor socket went down during stabilization.")
            L.warning("Exception: %s", str(e))
            L.error("Shouldn't self.successor be None at this point...?")
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

    # @chordnode.ChordNode.predecessor.getter
    # def predecessor(self):
    #     # Fall back to the closest preceding peer.
    #     if self._predecessor is None and self.peers:
    #         table = []  # [ (peer, distance) ]
    #         for peer in self.peers.lockfree_iter():
    #             dist = routing.moddist(int(peer.hash), int(self.hash),
    #                                    routing.HASHMOD)
    #             table.append((peer, dist))

    #         return min(table, key=lambda x: x[1])[0]

    #     return self._predecessor

    def _find_closest_peer_moddist(self, value, exclude=set()):
        """ Finds the closest known peer to a value using modular distance.

        NOTE: This uses `LockedSet.difference`, which returns a _regular set_.
              As such, it is _not threadsafe_. The returned set will not change
              through the runtime of this method, but it _may not_ guarantee
              that the resulting peer is actually alive and exists.
              Specifically,

                peers_before = set(self.peers)
                p = self._find_closest_peer_moddist(value)
                p in peers_before   # True
                peers_after = set(self.peers)
                p in peers_after    # True | False

              As such, you should beware of the validity of the returned peer.
        """
        if isinstance(value, routing.Hash): value = int(value)
        if not isinstance(value, int):
            raise TypeError("expected int, got %s" % type(value))

        table = []  # [ (peer, distance) ]
        for peer in self.peers.difference(exclude):
            dist = routing.moddist(value, int(peer.hash), routing.HASHMOD)
            table.append((peer, dist))

        near = min(table, key=lambda x: x[1])
        return near[0]

    def _find_closest_peer(self, value, exclude=set()):
        """ Finds the closest known peer responsible for a value.

        Each peer is responsible (as far as we're concerned) for the values in
        the range: (peer.predecessor.hash, peer.hash]. Thus, the peer that has
        the value fall into that range is the closest one we know.

        If a peer doesn't have a predecessor (as far as _they_ know), we can
        fake one for them by finding their predecessor in _our_ peer table.
        """
        pred = self.predecessor or self._find_closest_peer_moddist(value)
        for peer in self.peers.difference(exclude):
            iv = routing.Interval(int(pred.hash), int(peer.hash))
            if iv.within_open(value) or iv.end == value:    # (start, end]
                return peer

        return self._find_closest_peer_moddist(value, exclude)

    def __str__(self):
        return "[%s<-local(%s|peers=%d)->%s]" % (
            str(int(self.predecessor.hash)) if self.predecessor else None,
            self.compact, len(self.peers),
            str(int(self.successor.hash))   if self.successor   else None)
