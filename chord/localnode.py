import threading
import socket
import select
import random
import time

from . import utils
from . import hashring

from . import communication
from . import chordnode
from . import peer


class BaseMessage(object):
    def __init__(self, response_handler=lambda x: None,
                       request_handler=lambda x: None):
        self.handlers = (request_handler, response_handler)
        self.msg_type = ""
        pass

    @classmethod
    def parse(cls, bytestream):
        msg = cls()
        if not msg.parse_request(bytestream):
            if not msg.parse_response(bytestream):
                return False
        return msg

    @property
    def handler(self):
        assert self.msg_type, "No handler for an unparsed message."
        return self.handlers[0] if self.msg_type == "REQUEST" \
                                else self.handlers[1]


class InfoMessage(BaseMessage):
    """ Handles all processing of an INFO message.

    An INFO request from a `Peer` N contains nothing but the command.

    An INFO response back _to_ `Peer` N _from_ `LocalChordNode` X contains the
    following data:
        - X's hash value.
        - A 2-tuple address of X's predecessor.
        - A 2-tuple address of X's successor.

    This object allows you to do the following operations:
        - Build an INFO request from scratch.
        - Parse an INFO request from a bytestream.
        - Call a particular handler on a successful parsing.
    """
    def parse_request(self, bytestream):
        if bytestream.startswith("INFO\r\n"):
            self.msg_type = "REQUEST"
            return self.handlers[0](self, bytestream)

        return False

    def parse_response(self, bytestream):
        if not bytestream.startswith("INFO-R:") or \
           not bytestream.endswith("\r\n"):
            return False

        b = bytestream[len("INFO-R:") - 1 : -2]
        parts = b.split('|')
        self.node_hash = int(parts[0])
        self.pred_addr = parts[1].split(':')
        self.pred_addr[1] = int(self.pred_addr[1])
        self.succ_addr = parts[2].split(':')
        self.succ_addr[1] = int(self.succ_addr[1])

        self.msg_type = "RESPONSE"
        return self.handler(self, bytestream)

    def build_request(self):
        return "INFO\r\n"

    def build_response(self, node_hash, predecessor_addr, successor_addr):
        return "INFO-R:%d|%s:%d|%s:%d\r\n" % (node_hash,
            predecessor_addr[0], predecessor_addr[1],
            successor_addr[0], successor_addr[1])


class JoinMessage(BaseMessage):
    def parse_request(self, bytestream):
        if bytestream.startswith("JOIN\r\n"):
            self.msg_type = "REQUEST"
            return self.handlers[0](self, bytestream)

        return False

    def parse_response(self, bytestream):
        if not bytestream.startswith("JOIN-R:") or \
           not bytestream.endswith("\r\n"):
            return False

        b = bytestream[len("JOIN-R:") - 1 : -2]
        if b == "NONE":
            self.succ_addr = "NONE"
        else:
            self.succ_addr = b.split(',')

        self.msg_type = "RESPONSE"
        return self.handler(self, bytestream)

    def build_request(self):
        return "JOIN\r\n"

    def build_response(self, succ_addr):
        return "JOIN-R:%s" % ("NONE" if succ_addr is None else (
            "%s,%d" % succ_addr))


class DispatchThread(communication.InfiniteThread):
    """ Processes incoming messages from a list of sockets.
    """
    def __init__(self, parent):
        super(DispatchThread, self).__init__()
        self.read_queue = communication.ReadQueue()
        self.handler = parent
        self.peers = { }    # dict -> { socket: (Peer, ReadQueue) }

    def add_peer(self, client_socket, client_address):
        peer_obj = peer.Peer(client_socket, client_address)
        self.peers[peer_obj.peer_sock] = (peer_obj, communication.ReadQueue())

    def _loop_method(self):
        if not self.peers:
            return

        # Only try reading from the open peers. The list will be properly
        # filtered later (TODO).
        useable = [
            pair[0].peer_sock for pair in filter(
                lambda x: not x[0].complete, self.peers.values())
        ]
        rd, wr, er = select.select(useable, [ ], useable, 1)

        for sock in rd:
            peer, queue = self.peers[sock]
            if not queue.read(sock):
                print "Socket for %s closes." % peer.remote_addr
                peer.complete = True
                continue

            while queue.ready:
                msg = queue.pop()
                self.handler.process(peer, msg)

        if er:
            print "An error occurred in the socket."
            self.stop_running()


class LocalChordNode(chordnode.ChordNode):
    """ Represents the current local node in the Chord hash ring.

    Specifically, this means the node exists *on this machine* and that no
    remote lookups or network communication is necessary.
    """

    def __init__(self, data, bind_addr=('localhost', 2017)):
        print "__init__(%s, %s)" % (data, bind_addr)

        # This socket is responsible for inbound connections (from new potential
        # nodes). It is always in an "accept" state in a separate thread.
        self.local_addr = bind_addr
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(self.local_addr)
        self.listener.listen(5)

        print "Starting listener thread for", self.listener.getsockname()
        self.listen_thread = communication.ListenerThread(self, self.listener)
        self.listen_thread.start()

        # This thread is responsible for handling the messages from all of the
        # peers we're connected to.
        self.dispatcher = DispatchThread(self)
        self.dispatcher.start()

        # This socket is used exclusively for joining a Chord ring. Once a node
        # has joined a ring, this reference is removed and the socket is just a
        # part of the peer list.
        self.joiner = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # These are all of the known direct neighbors in the Chord ring.
        self.peers = [ ]

        super(LocalChordNode, self).__init__(data)

    @utils.listify
    def add_node(self, node):
        """ Adds a node to the internal finger table.

        This means proper ordering in the finger table with respect to the
        node's hash value.
        """
        self.pr("add_node::self", str(self))
        self.pr("add_node::node", str(node))
        assert isinstance(node, chordnode.ChordNode), \
               "add_node: not a ChordNode object!"

        self.fingers.insert(node)

    @utils.listify
    def remove_node(self, node):
        """ Indicates a node has disconnected / failed in the Chord ring.
        """
        self.pr("remove_node:", str(self), str(node))
        assert isinstance(node, chordnode.ChordNode), \
               "remove_node: not a ChordNode object!"

        self.fingers.remove(node)

        #
        # If this node used to be our successor, replace it with the next
        # available node. Likewise with the predecessor, except the previous
        # available node.
        #
        # If this was the last node in the ring (excluding us) this should
        # properly trigger the "first node" code path in `nodeJoined()`.
        #

        if self.successor is node:
            self.successor = self.fingers.findSuccessor(node.hash + 1)

        if self.predecessor is node:
            self.predecessor = self.fingers.findPredecessor(node.hash - 1)

    def join_ring(self, homie):
        """ Joins a Chord ring using a specified node as its "entry".

        We use the stabilization technique outlined in the Chord paper, which
        means that a join only involves asking our homie for our immediate
        successor. Then, we set that to be our successor.
        """
        self.pr("join_ring:", str(self), str(homie))

        assert self.fingers.real_length <= 1, "join_ring: existing nodes!"
        assert self.predecessor is None,     "join_ring: predecessor set!"

        self.predecessor = None

        #
        # Create a Peer object that represents the external node that we are
        # using to join the ring. After this JOIN request has been processed
        # (that is, the RJOIN response has been received), the joiner socket is
        # moved to the peer list.
        #
        # After this, the peer list contains, additionally, the successor of us
        # as well as the peer we used to join the ring.
        #
        p = peer.Peer(self.joiner, homie)
        succ = p.join_ring()

        self.add_node(succ)
        self.peers.append(p)
        self.peers.append(succ)

        assert self.successor == succ, "Invalid successor!"

    def stabilize(self):
        """ Runs the stabilization algorithm.

        Stabilizing means asking our successor, n, "for the successor's
        predecessor p, and decid[ing] whether p should be [our] successor
        instead." Then, we tell n's successor about n. That way, the successor
        can learn about n if it didn't already know in the first place.
        """
        if self.successor is None:  # nothing to stabilize, yet
            return

        import pdb; pdb.set_trace()
        x = self.successor.get_predecessor()

        # If our successor doesn't *have* a predecessor, tell them about us, at
        # least! That way, the ring is linked.
        if x is None:
            assert isinstance(self.successor, Peer)
            self.successor.notify(self)
            return

        # We HAVE to use an open-ended range check, because if our successor's
        # predecessor is us (as it would be in the normal case), we'd be setting
        # us as our own successor!
        if self.fingers.local.within_open(x.hash):
            self.fingers.set_successor(x)
        self.successor.notify(self)

    def fix_fingers(self):
        """ This ensures that the finger table is current.
        """
        index = random.randint(1, len(self.fingers) - 1)
        thumb = self.finger(index)
        if thumb.node is None:
            return

        # self.pr("fix_fingers: fixing finger(%d)" % index)
        # self.pr("fix_fingers: fingers are\n%s" % self.fingers)
        thumb.node = self.fingers.findSuccessor(thumb.start)
        # self.pr("fix_fingers: fingers are now\n%s" % self.fingers)

    def process(self, peer, message):
        print "Peer %s received message %s" % (peer.remote_addr, repr(message))

        handlers = [
            InfoMessage(
                request_handler=lambda msg, b: self.on_info_request(peer, msg),
            ),
            JoinMessage(
                request_handler=lambda msg, b: self.on_node_joined(peer, msg)
            ),
        ]

        for handler in handlers:
            if handler.parse_request(message) or \
               handler.parse_response(message):
                break

        return

        if message == "NOTIFY":
            msg = "NOTIFY-R"
            self.on_notify(peer, message)
            msg += "%s:%d" % self.predecessor.remote_addr
            peer.peer_sock.sendall(msg)

    def on_info_request(self, peer_object, message):
        if self.predecessor is None:
            pred_addr = self.listener.getsockname()
        else:
            pred_addr = self.predecessor.remote_addr

        msg = InfoMessage().build_response(self.hash,
            self.successor.remote_addr, pred_addr)

        self.pr("Responding to INFO with %s" % repr(msg))
        peer_object.peer_sock.sendall(msg)

    def on_node_joined(self, peer_object, message):
        """ Receives a JOIN message from a node previously outside the ring.

        Chord specifies that this occurs when a new node joins the ring and
        chooses us as its successor. Thus, we use this node to (potentially)
        establish our predecessor.

        If it's our first node, though, it also gets added to the finger table!

        The response is an RJOIN containing the would-be successor information
        of the incoming Peer. If we're the only ones in the ring, we return
        "NONE" and let them use our remote address.
        """

        self.pr("node_joined::self", str(self))
        self.pr("node_joined::homie", str(peer_object))

        assert isinstance(peer_object, peer.Peer), \
               "node_joined: invalid node!"

        # Always add node, because it could be better than some existing ones.
        self.add_node(peer_object)

        # Is this node closer to us than our existing predecessor?
        if self.predecessor is None or \
           hashring.Interval(
                self.predecessor.hash, self.hash).within(peer_object.hash):
            self.predecessor = peer_object

    def on_notify(self, node, message):
        """ Determine whether or not a node should be our predecessor.
        """
        self.pr("notify: trying", node)
        if self.predecessor is None or \
           hashring.Interval(self.predecessor.hash, self.hash).within(node):
            self.predecessor = node

        assert self.predecessor != self, "notify: set self as predecessor!"

