""" Defines a local Chord node.

This is the object you want to use to begin structuring a Chord ring on your
machine. At this point, you can either join an existing ring (by using the
`LocalNode.join_ring` method), or simply by waiting for a node to join this
ring.

 TODO LIST
===========
This is a list for development, as opposed to the README list which is more of a
"big picture" list for full modules and concepts.

- [?] Why does this cause a crash?
            thumb.node = self.fingers.find_successor(thumb.start)
      Only sometimes, with two nodes -- seems consistent with 3+ nodes.
- [*] Figure out why the NOTIFY message sends every time -- in theory, we should
      only need to send it when we know that the node doesn't know about us.
- [ ] In `on_info_response`, actually parse and process the message and fill the
      local node reference with the updated information.
- [*] Optimize hashing to not pack/unpack unecessarily. I probably need to add
      some sort of `Hash` object -- this way, I can preserve the previous info
      in addition to the hash itself.
- [*] Add more verbose / informative `level=INFO` logging.
- [ ] Add custom exceptions for the Chord protocol aspects itself, rather than
      just various `UnpackException`s.
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
            return
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

        self._hash = fingertable.Hash(data)
        super(LocalNode, self).__init__(bind_addr)
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
        joiner_peer = self.add_peer(remote_address, remote_address)
        join_msg = chordpkt.JoinRequest.make_packet(self.hash, self.local_addr)
        if not self.processor.request(joiner_peer.peer_sock, join_msg,
                                      self.on_join_response, timeout):
            raise ValueError("JOIN request didn't get a response in time.")

        return join_msg

    def add_peer(self, address, listener, peer_socket=None, peer_hash=None):
        """ From an arbitrary remote address, add a RemoteNode to the ring.
        """
        L.debug("add_peer::hash: %s", hash)
        L.debug("add_peer::address: %s", address)
        L.debug("add_peer::listener_addr: %s", listener)
        L.debug("add_peer::peer_socket: %s", peer_socket)

        p = remotenode.RemoteNode(peer_hash, address, listener,
            existing_socket=peer_socket)

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

        if self.successor.predecessor.hash == self.hash:
            L.debug("Nothing to notify -- we are successor.predecessor")
            return

        # We need to now notify our new successor about ourselves, so that they
        # can adjust their tables accordingly as well.
        notif_msg = chordpkt.NotifyRequest.make_packet()

        L.info("Notifying our neighbor (%s:%d) about us.",
            *self.successor.remote_addr)

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

            # import pdb; pdb.set_trace()
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
            L.info("    The first hop was: %d", lookup_rsp.node)
            L.info("    The hash of the neighbor is: %d", lookup_rsp.mapped)
            L.info("    The nearest neighbor is listening on: %s:%d", *lookup_rsp.listener)

        else:
            # L.info("    Local entry found!")
            # L.info("    Current successor: %d", thumb.node.hash)
            # L.info("    Best successor: %d", predecessor.successor.hash)
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
            "" if graceful else "not ", node)

        self.peers.remove(node)
        self.fingers.remove(node)

    def on_new_peer(self, client_address, client_socket):
        """ Creates a new Peer from a socket that just joined this ring.
        """
        self.processor.add_socket(client_socket, self.process)

    def on_info_request(self, sock, msg):
        if self.predecessor is None:
            pred_addr = self.listener.getsockname()
        else:
            pred_addr = self.predecessor.remote_addr

        infor_msg = chordpkt.InfoResponse.make_packet(
            self.hash, self.successor.hash, self.successor.remote_addr,
            original=msg)

        L.info("Peer (%s:%d) requested info about us, replying...", *sock.getpeername())
        L.info("Our details:")
        L.info("    Hash: %d", self.hash)
        L.info("    Predecessor: %s", self.predecessor)
        L.info("    Successor: %s", self.successor)

        self.processor.response(sock, infor_msg)
        return True

    @prevent_nonpeers
    def on_info_response(self, sock, node, msg):
        """ Processes a peer's information from an INFO response.
        """
        L.debug("on_info_response::sock: %s", sock.getsockname())
        L.debug("on_info_response::msg:  %s", msg)

        info_resp = chordpkt.InfoResponse.unpack(msg.data)

        L.info("Received info from a peer: %d", info_resp.sender_hash)
        L.info("    Successor hash: %d", info_resp.succ_hash)
        L.info("    Successor listening on: %s:%d", *info_resp.listener)

        assert node.hash == info_resp.sender_hash, "Hashes don't match!"

        # node.

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

        L.debug("node_joined::self: %s", str(self))
        L.debug("node_joined::sock: %s", str(sock))
        L.debug("node_joined::msg:  %s", repr(msg))

        L.info("Peer (%s:%d) requested to join the network.", *sock.getpeername())

        req = chordpkt.JoinRequest.unpack(msg.data)

        # Always add node, because it could be better than some existing ones.
        p = self.add_peer(sock.getpeername(), req.listener, sock, req.node_hash)
        self.add_node(p)

        # Is this node closer to us than our existing predecessor?
        if self.predecessor is None or \
           fingertable.Interval(self.predecessor.hash, self.hash).within(p.hash):
            self.predecessor = p

        # If our successor doesn't exist, or matches the address of the
        # requestee (that is, it's just us and them), we need to make sure that
        # we tell them that _we_ are their successor instead of telling them our
        # actual successor.
        #
        # This prevents a loop of connections in a small ring.
        if not self.successor or self.successor.local_addr == req.listener:
            response_object = self
        else:
            response_object = self.successor

        L.info("Allowing connection and responding with our details:")
        L.info("    Our hash: %d", self.hash)
        L.info("    Requestee successor hash: %d", response_object.hash)
        L.info("    Requestee successor listener: %s:%d",
            *response_object.local_addr)

        response = chordpkt.JoinResponse.make_packet(self.hash,
            response_object.hash, response_object.local_addr, original=msg)

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
        L.info("    From peer with hash: %d", joinr_msg.sender_hash)
        L.info("    Successor hash: %d", joinr_msg.succ_hash)
        L.info("    Successor address: %s:%d", *joinr_msg.listener)

        result = self._peerlist_contains(joinr_msg.listener)
        if result is not None:
            L.info("    We already know about this peer.")
            L.info("    This means they are the closest node to us!")

            # We set an empty hash when we added the peer, so now we need to
            # update it to be accurate.
            result._hash = joinr_msg.succ_hash

        else:
            L.info("    Connecting to our provided successor.")
            result = self.add_peer(sock.getsockname(), joinr_msg.listener,
                peer_hash=joinr_msg.succ_hash)

        assert result.hash == joinr_msg.succ_hash, \
            "Hashes don't match! %s vs. %s" % (repr(result.hash),
                repr(joinr_msg.succ_hash))

        self.add_node(result)

        if self.successor != result:
            L.critical("Somehow ended up with an invalid successor!")
            raise ValueError("Invalid successor from JOIN response.")

        return True

    @prevent_nonpeers
    def on_notify_request(self, sock, node, msg):
        """ Determine whether or not a node should be our predecessor.
        """
        L.debug("notify::sock: %s", sock)
        L.debug("notify::msg:  %s", msg)

        if self.predecessor is None or \
           fingertable.Interval(self.predecessor.hash, self.hash).within(node):

            L.info("Another peer is a better predecessor:")
            L.info("    Node hash: %d", node.hash)

            if node.predecessor is not None:
                L.info("    Node predecessor hash: %d", node.predecessor.hash)
                L.info("    Node predecessor address: %s:%d",
                    *node.predecessor.local_addr)
            else:
                L.warning("    Node has no predecessor!")

            self.predecessor = node

        if self.predecessor == self:
            L.critical("We set ourselves as our own predecessor!")
            raise ValueError

        notify_msg = chordpkt.NotifyResponse.make_packet(
            self.hash, self.successor, self.predecessor, original=msg)

        self.processor.response(sock, notify_msg)
        return True

    def on_notify_response(self, sock, msg):
        notif_msg = chordpkt.NotifyResponse.unpack(msg.data)

    def on_lookup_request(self, sock, msg):
        """ TODO: Make this work asynchronously (ex: `self.pending_lookups`).
            TODO: Unify this with `self.fix_fingers`.
        """
        lookup_rq = chordpkt.LookupRequest.unpack(msg.data)
        L.info("Received a lookup request from %d for %d",
               lookup_rq.sender, lookup_rq.lookup)

        h = lookup_rq.lookup
        # import pdb; pdb.set_trace()
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
            L.info("    The hash of the neighbor is: %d", lookup_rsp.mapped)
            L.info("    The nearest neighbor is listening on: %s:%d",
                   *lookup_rsp.listener)

        else:
            L.info("    Local entry found!")
            L.info("    Current successor: %d", h)
            L.info("    Best successor: %d", pred.successor.hash)

            lookup_rsp = chordpkt.LookupResponse.make_packet(self.hash, h,
                pred.successor.hash, pred.successor.local_addr, original=msg)

        self.processor.response(sock, lookup_rsp)


    def _peerlist_contains(self, elem):
        if isinstance(elem, tuple):
            for peer in self.peers:
                if peer.remote_addr == elem:
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
        return "<LocalNode | hash=%d,pred=%s,succ=%s>" % (self.hash,
            str(int(self.predecessor.hash)) if self.predecessor else None,
            str(int(self.successor.hash))   if self.successor   else None)
