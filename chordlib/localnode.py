""" Defines a local Chord node.

This is the object you want to use to begin structuring a Chord ring on your
machine. At this point, you can either join an existing ring (by using the
`LocalNode.join_ring` method), or simply by waiting for a node to join this
ring.
"""

import threading
import socket
import select
import random
import time

from chordlib import L
from chordlib import utils as chutils
from chordlib import fingertable

from chordlib import commlib
from chordlib import chordnode
from chordlib import remotenode

import packetlib
from   packetlib import chord as chordpkt
from   packetlib import utils as pktutils


def prevent_nonpeers(fn):
    """ Prevent receiving messages from peers we don't know about.

    This adds an additional parameter to the method -- the node itself that was
    found. More often than not, we don't care about the raw socket, so this is
    more useful.

    FIXME: Is there a reason to keep the original socket? Maybe we don't need
           the extra parameter at all.
    """
    def wrapper(self, sock, *args, **kwargs):
        node = self._peerlist_contains(sock)
        if node is None:
            L.warning("This message is from an unknown peer.")
            L.warning("    Socket: %s:%d", *sock.getpeername())
            return False
        return fn(self, sock, node, *args, **kwargs)
    return wrapper


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

        # These are all of the known direct neighbors in the Chord ring.
        self.peers = []

        super(LocalNode, self).__init__(fingertable.Hash(data),
            self.listener.getsockname())

        L.info("Created Chord peer with hash: %d", self.hash)
        self.data = data

        # This thread periodically performs the stabilization algorithm.
        self.stable = chordnode.Stabilizer(self)
        self.stable.start()

        L.debug("starting stabilizer")

    def join_ring(self, remote_address, timeout=10):
        """ Joins a Chord ring through a node at the specified address.

        We use the stabilization technique outlined in the Chord paper, which
        means that a JOIN only involves asking our entry point for our immediate
        successor.

        :remote_address     the address referring to a node in a Chord ring.
        :timeout[=30]       the number of seconds to wait for a response.
        """
        remote_address = (socket.gethostbyname(remote_address[0]),
                          remote_address[1])

        L.debug("join_ring::self: %s", str(self))
        L.debug("join_ring::addr: %s", str(remote_address))

        assert self.fingers.real_length <= 1, "join_ring: existing nodes!"
        assert self.predecessor is None,      "join_ring: predecessor set!"

        #
        # Create a Peer object that represents the external node that is letting
        # us into the ring. We send a JOIN request to the address, expecting a
        # response indicating our would-be successor.
        #
        # We validate this by establishing a connection to the successor and
        # adding it to our peer list.
        #

        L.info("Joining peer ring via %s:%d.", *remote_address)
        joiner_peer = self.add_peer(remote_address)
        join_msg = chordpkt.JoinRequest.make_packet(self.hash, self.chord_addr)
        if not self.processor.request(joiner_peer.peer_sock, join_msg,
                                      self.on_join_response, timeout):
            raise ValueError("JOIN request didn't get a response in time.")

        return join_msg

    def add_peer(self, listening_on, peer_socket=None, peer_hash=None):
        """ From an arbitrary remote address, add a RemoteNode to the ring.
        """
        L.debug("add_peer::listening_on: %s", listening_on)
        L.debug("add_peer::peer_hash: %s", peer_hash)
        if peer_socket is not None:
            L.debug("add_peer::peer_socket: %s->%s", peer_socket.getpeername(),
                    peer_socket.getsockname())
        else:
            L.debug("add_peer::peer_socket: %s", peer_socket)

        p = remotenode.RemoteNode(peer_hash, listening_on, peer_socket)

        self.peers.append(p)
        self.processor.add_socket(p.peer_sock,
            lambda s, msg: self.process(s, msg))

        return p

    def remove_node(self, node):
        """ Indicates a node has disconnected / failed in the Chord ring.
        """
        self.pr("remove_node::self", str(self))
        self.pr("remote_addr::node", str(node))
        assert isinstance(node, chordnode.ChordNode), \
               "remove_node: not a ChordNode object!"

        self.fingers.remove(node)

        #
        # If this node used to be our successor, replace it with the next
        # available node. Likewise with the predecessor, except the previous
        # available node.
        #
        # If this was the last node in the ring (excluding us) this should
        # properly trigger the "first node" code path in `on_node_joined`.
        #

        if self.successor is node:
            self.successor = self.fingers.find_successor(node.hash + 1)

        if self.predecessor is node:
            self.predecessor = self.fingers.find_predecessor(node.hash - 1)

    def stabilize(self):
        """ Runs the stabilization algorithm.

        Stabilizing means asking our successor, n, "for the successor's
        predecessor p, and decid[ing] whether p should be [our] successor
        instead." Then, we tell n's successor about n. That way, the successor
        can learn about n if it didn't already know in the first place.
        """
        if self.successor is None:  # nothing to stabilize, yet
            return

        # If we haven't attempted to query the predecessor yet, do so.
        #
        # If that fails, the successor may not *have* a predecessor, in which
        # case we should tell them about us, at least! That way, the ring is
        # linked.
        if self.successor.predecessor is None:
            L.info("Asking our successor for neighbor info...")
            info_msg = chordpkt.InfoRequest.make_packet()
            info_rsp = self.processor.request(self.successor.peer_sock,
                info_msg, self.on_info_response, wait_time=5)

            if not info_rsp:
                L.error("on_info_response failed.")
                return

            if self.successor.predecessor is None:
                self.successor.predecessor = self

        x = self.successor.predecessor

        # We HAVE to use an open-ended range check, because if our successor's
        # predecessor is us (as it would be in the normal case), we'd be setting
        # us as our own successor!
        if self.fingers.local.within_open(x.hash):
            L.info("Our successor's predecessor is closer to us than our ")
            L.info("current successor!")
            L.info("    Specifically, successor.predecessor: %d", x.hash)
            L.info("    Whereas self.successor: %d", x.hash)
            L.info("    And self.range: [%d, %d)",
                   self.fingers.local.start, self.fingers.local.end)

            L.critical("Entering a NotImplemented code path!")
            # self.fingers.set_successor(x)

        if x.hash == self.hash:
            L.debug("Nothing to notify -- we are successor.predecessor")
            return

        # We need to now notify our new successor about ourselves, so that they
        # can adjust their tables accordingly as well.
        notif_msg = chordpkt.NotifyRequest.make_packet()

        L.info("Notifying our neighbor (%s:%d) about us.",
               *self.successor.chord_addr)

        # We don't care about the response, so just fire away.
        self.processor.request(self.successor.peer_sock, notif_msg,
            lambda *args: True, wait_time=0)

    def fix_fingers(self):
        """ This ensures that the finger table is current.
        """
        index = random.randint(1, len(self.fingers) - 1)
        thumb = self.finger(index)
        if thumb.node is None:
            return

        L.info("Looking up successor of %d[i=%d] to validate routing table.",
               thumb.start, index)

        # Only look up the predecessor because if it doesn't exist locally, the
        # successor will be `None`.
        predecessor = self.fingers.find_predecessor(thumb.start)

        # Perform iterative lookup for nodes that we need more information on.
        if isinstance(predecessor, remotenode.RemoteNode) and \
           predecessor.successor is None:

            L.info("    Failed to look up locally!")
            L.info("    The nearest local neighbor is: %d", predecessor.hash)
            L.info("    Performing a remote lookup!")

            lookup_msg = chordpkt.LookupRequest.make_packet(self.hash,
                fingertable.Hash(hashed=thumb.start))

            response_data = []
            def callback(*args):
                for item in args: response_data.append(item)
                return True

            result = self.processor.request(predecessor.peer_sock,
                lookup_msg, callback, wait_time=120)

            if not result or not response_data:
                L.warning("Finding the successor of %s[%d] failed.", thumb, index)
                import pdb; pdb.set_trace()
                raise ValueError("Failed to look up successor!")

            lookup_rsp = chordpkt.LookupResponse.unpack(response_data[1].data)
            assert thumb.start == lookup_rsp.lookup

            L.info("Completed lookup for hash=%d:", lookup_rsp.lookup)
            L.info("    The first hop was: %d", lookup_rsp.sender)
            L.info("    The hash of the neighbor is: %d", lookup_rsp.mapped)
            L.info("    The nearest neighbor is listening on: %s:%d",
                   *lookup_rsp.listener)

        elif predecessor.successor is not None:
            L.info("    Local entry found!")
            L.info("    Current successor: %d", thumb.node.hash)
            L.info("    Best successor: %d", predecessor.successor.hash)
            thumb.node = predecessor.successor

    def process(self, peer_socket, msg):
        if peer_socket is None:     # socket closed?
            L.error("RemoteNode shut down!")
            return

        L.debug("Received message %s from %s:%d", repr(msg),
            peer_socket.getsockname()[0], peer_socket.getsockname()[1])

        handlers = {
            packetlib.MessageType.MSG_CH_JOIN:      self.on_join_request,
            packetlib.MessageType.MSG_CH_INFO:      self.on_info_request,
            packetlib.MessageType.MSG_CH_NOTIFY:    self.on_notify_request,
            packetlib.MessageType.MSG_CH_LOOKUP:    self.on_lookup_request,
        }

        for msg_type, func in handlers.iteritems():
            if msg.type == msg_type:
                func(peer_socket, msg)
                break
        else:
            raise ValueError("Message received (type=%s) without handler." % (
                message.MessageType.LOOKUP[msg.type]))

    @prevent_nonpeers
    def on_error(self, closed_sock, node, graceful):
        """ Removes a peer from internal structures.

        TODO: Notify neighbors that the node went down.
        """
        L.warning("Neighbor went down %sgracefully: %s",
            "" if graceful else "un", node)

        self.peers.remove(node)
        self.fingers.remove(node)

    def on_new_peer(self, client_address, client_socket):
        """ Creates a new Peer from a socket that just joined this ring.
        """
        self.processor.add_socket(client_socket, self.process)

    def on_info_request(self, sock, msg):
        """ Processes an INFO message and responds with our ring details.
        """

        #
        # TODO: Race condition between JOIN response and INFO request? Consider:
        #   - A joins B, sending JOIN request.
        #   - B responds, sending JOIN-RESP.
        #   - B calls stabilization, sending INFO.
        #   - A hasn't processed the JOIN-RESP yet.
        #   - A receives INFO, this assertion is triggered.
        #
        if self.predecessor is None and self.successor is None:
            L.warning("Received a request for information, but we aren't done "
                      "processing our join request yet!")
            return

        pred = self.predecessor or self.successor
        succ = self.successor   or pred

        infor_msg = chordpkt.InfoResponse.make_packet(
            self.hash, pred, succ, original=msg)

        L.info("Peer (%s:%d) requested info about us, replying...",
               *sock.getpeername())
        L.info("Our details:")
        L.info("    Hash: %d", self.hash)
        L.info("    Predecessor: %s", pred)
        L.info("    Successor: %s", succ)

        self.processor.response(sock, infor_msg)
        return True

    @prevent_nonpeers
    def on_info_response(self, sock, node, msg):
        """ Processes a peer's information from an INFO response.
        """
        L.debug("on_info_response::sock: %s", sock.getsockname())
        L.debug("on_info_response::msg:  %s", msg)

        info_resp = chordpkt.InfoResponse.unpack(msg.data)

        L.info("Received info from a peer: %d", info_resp.sender)
        L.info("    Successor hash: %d on %s:%d", info_resp.succ_hash,
               *info_resp.succ_addr)
        L.info("    Predecessor hash: %d on %s:%d", info_resp.pred_hash,
               *info_resp.pred_addr)

        assert node.hash == info_resp.sender, "Hashes don't match!"

        if node.successor is not None:
            L.info("Removing old successor from node %d!", node.successor.hash)
            node.fingers.remove(node.successor)

        node.fingers.insert(info_resp.successor)
        node.predecessor = info_resp.predecessor

        return info_resp

    def on_join_request(self, sock, msg):
        """ Receives a JOIN request from a node previously outside the ring.

        Chord specifies that this occurs when a new node joins the ring and
        chooses us as its successor. Thus, we use this node to (potentially)
        establish our predecessor.

        If it's our first node, though, it also gets added to the finger table!

        The response is an RJOIN containing the would-be successor information
        of the incoming Peer. If we're the only ones in the ring, we return
        "NONE" and let them use our remote address.
        """

        L.debug("on_join_request::self: %s", str(self))
        L.debug("on_join_request::sock: %s", str(sock))
        L.debug("on_join_request::msg:  %s", repr(msg))
        L.info("Peer (%s:%d) requested to join the network.", *sock.getpeername())

        req = chordpkt.JoinRequest.unpack(msg.data)

        # Always add node, because it could be better than some existing ones.
        p = self.add_peer(req.listener, peer_socket=sock, peer_hash=req.sender)
        self.add_node(p)

        # Is this node closer to us than our existing predecessor?
        if self.predecessor is None or \
           fingertable.Interval(self.predecessor.hash, self.hash).within(p.hash):
            L.info("Setting joinee as our predecessor!")
            self.predecessor = p

        #
        # If our successor doesn't exist, or matches the address of the
        # requestee (that is, it's just us and them), we need to make sure that
        # we tell them that _we_ are their successor instead of telling them our
        # actual successor.
        #
        # This prevents a loop of connections in a small ring.
        #
        if not self.successor or self.successor.chord_addr == req.listener:
            response_object = self
        else:
            response_object = self.successor

        L.info("Allowing connection and responding with our details:")
        L.info("    Our hash: %d", self.hash)
        L.info("    Our successor hash: %d on %s:%d", self.successor.hash,
               *self.successor.chord_addr)
        L.info("    Our predecessor hash: %d on %s:%d", self.predecessor.hash,
               *self.predecessor.chord_addr)
        L.info("    Requestee successor hash: %d on %s:%d",
               response_object.hash, *response_object.chord_addr)

        response = chordpkt.JoinResponse.make_packet(response_object,
            self.hash, self.predecessor, self.successor, original=msg)

        assert self.predecessor != self

        self.processor.response(sock, response)
        return True

    def on_join_response(self, sock, msg):
        """ Executed when an JOIN _response_ is received.
        """
        L.debug("join_response::self: %s", self)
        L.debug("join_response::sock: %s", sock)
        L.debug("join_response::msg:  %s", msg)

        joinr_msg = chordpkt.JoinResponse.unpack(msg.data)

        L.info("We have been permitted to join the network:")
        L.info("    From peer with hash: %d", joinr_msg.sender)
        L.info("    Sender successor hash: %d on %s:%d",
               joinr_msg.succ_hash, *joinr_msg.succ_addr)
        L.info("    Sender predecessor hash: %d on %s:%d",
               joinr_msg.pred_hash, *joinr_msg.pred_addr)
        L.info("    Our new predecessor hash: %d on %s:%d",
               joinr_msg.req_succ_hash, *joinr_msg.req_succ_addr)

        import pdb; pdb.set_trace()
        result = self._peerlist_contains(joinr_msg.req_succ_addr)
        if result is not None:
            L.info("    We already know about this peer.")
            L.info("    This means they are the closest node to us!")

            # We set an empty hash when we added the peer, so now we need to
            # update it to be accurate.
            result._hash = joinr_msg.request_successor.hash

        elif joinr_msg.request_successor.hash == self.hash:
            L.info("    Our neighbor indicated that WE are our successor.")
            L.info("    That means he should be our true successor.")
            result = self._peerlist_contains(sock)

        else:
            L.info("    Connecting to our provided successor.")
            result = self.add_peer(
                joinr_msg.request_successor.chord_addr,
                peer_hash=joinr_msg.request_successor.hash)

        self.add_node(result)

        if self.successor != result:
            L.critical("Somehow ended up with an invalid successor!")
            raise ValueError("Invalid successor from JOIN response.")

        return True

    @prevent_nonpeers
    def on_notify_request(self, sock, node, msg):
        """ Determine whether or not a node should be our predecessor.
        """
        L.debug("notify::sock: %s->%s", sock.getpeername(), sock.getsockname())
        L.debug("notify::msg:  %s", msg)

        if self.predecessor is None or fingertable.Interval(
            self.predecessor.hash, self.hash).within(node.hash):

            L.info("Another peer is a better predecessor:")
            L.info("    Node hash: %d", node.hash)

            if node.predecessor is not None:
                L.info("    Node predecessor hash: %d on %s:%d",
                       node.predecessor.hash, *node.predecessor.chord_addr)
            else:
                L.warning("    Node has no predecessor!")

            self.predecessor = node

        if self.predecessor == self:
            L.critical("We set ourselves as our own predecessor!")
            raise ValueError

        notify_msg = chordpkt.NotifyResponse.make_packet(
            self.hash, self.predecessor, self.successor, original=msg)

        self.processor.response(sock, notify_msg)
        return True

    @prevent_nonpeers
    def on_notify_response(self, sock, node, msg):
        notif_msg = chordpkt.NotifyResponse.unpack(msg.data)

        L.info("Received a notification from a peer: %d", notif_msg.sender)
        L.info("    Successor hash: %d on %s:%d",
               notif_msg.succ_hash, *notif_msg.listener)
        L.info("    Predecessor hash: %d on %s:%d",
               notif_msg.pred_hash, *notif_msg.pred_addr)

        assert node.hash == notif_msg.node_hash, "Hashes don't match!"

        node.fingers.remove(node.successor)
        node.fingers.insert(notif_msg.successor)
        node.predecessor = notif_msg.predecessor

        return notif_msg

    def on_lookup_request(self, sock, msg):
        """ TODO: Make this work asynchronously (ex: `self.pending_lookups`).
            TODO: Unify this with `self.fix_fingers`.
        """
        lookup_rq = chordpkt.LookupRequest.unpack(msg.data)
        L.info("Received a lookup request from %d for %d",
               lookup_rq.sender, lookup_rq.lookup)

        h = lookup_rq.lookup
        pred = self.fingers.find_predecessor(h)

         # Perform iterative lookup for nodes that we need more information on.
        if isinstance(pred, remotenode.RemoteNode) and \
           pred.successor is None:

            L.info("    Failed to look up locally!")
            L.info("    The nearest local neighbor is: %d", pred.hash)
            L.info("    Performing a remote lookup!")

            lookup_msg = chordpkt.LookupRequest.make_packet(self.hash,
                fingertable.Hash(hashed=h))

            response_data = []
            def callback(*args):
                global response_data
                response_data = args
                return True

            result = self.processor.request(pred.peer_sock,
                lookup_msg, callback, wait_time=120)

            if not result:
                L.warning("Finding the successor of %s failed.", h)
                import pdb; pdb.set_trace()
                return

            lookup_rsp = chordpkt.LookupResponse.unpack(response_data[1])
            assert h == lookup_rsp.lookup

            lookup_rsp  = chordpkt.LookupResponse.make_packet(self.hash,
                lookup_rsp.lookup, lookup_rsp.mapped, lookup_rsp.listener,
                hops=lookup_rsp.hops + 1)

            L.info("Completed lookup for hash=%d:", lookup_rsp.lookup)
            L.info("    Hop 1/%d was: %d", lookup_rsp.hops, lookup_rsp.node)
            L.info("    The hash of the nearest neighbor is: %d on %s:%d",
                   lookup_rsp.mapped, *lookup_rsp.listener)

        else:
            L.info("    Local entry found!")
            L.info("    Current successor: %d", h)
            L.info("    Best successor: %d", pred.successor.hash)

            lookup_rsp = chordpkt.LookupResponse.make_packet(self.hash, h,
                pred.successor.hash, pred.successor.chord_addr, original=msg)

        self.processor.response(sock, lookup_rsp)

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

    def __str__(self):
        return "<LocalNode(%s:%d) | hash=%d,pred=%s,succ=%s>" % (
            self.chord_addr[0], self.chord_addr[1], self.hash,
            str(int(self.predecessor.hash)) if self.predecessor else None,
            str(int(self.successor.hash))   if self.successor   else None)
