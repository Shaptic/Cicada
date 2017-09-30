#!/usr/bin/python2

import random
import socket
import functools

from   chordlib  import commlib, L
from   packetlib import message
import chordlib.utils   as chutils
import packetlib.chord  as chordpkt


class HeartbeatManager(object):
    """ Maintains connections between peers.
    """

    class PingThread(chutils.InfiniteThread):
        """ Sends pings to who we care about: predecessor and successor.
        """
        def __init__(self, peerlist, parent):
            super(HeartbeatManager.PingThread,
                  self).__init__(name="PingThread-%s" % str(int(parent.hash))[:4],
                                 pause=5)

            self.peerlist = peerlist
            self.processor = parent.processor
            self.parent = parent

        def _loop_method(self):
            fn = functools.partial(self._peer_filter, self.parent)
            for peer in filter(fn, self.peerlist):
                ping = chordpkt.PingMessage(self.parent.hash)
                msg = message.MessageContainer(ping.TYPE, data=ping.pack())

                L.info("Sending a PING with message %d.", ping.value)
                handler = functools.partial(self.on_pong, ping.value)
                self.processor.request(peer.peer_sock, msg, handler,
                                       wait_time=0)

        def on_pong(self, ping_value, socket, message):
            """ Validates a PONG value to an initial PING.
            """
            pong = chordpkt.PongMessage.unpack(message.data)
            L.info("Received a PONG response %d for our previous PING %d.",
                   pong.value, ping_value)

            if pong.value != ping_value:
                L.warning("Received an invalid PONG response.")
                return False

            result = filter(lambda x: x.hash == pong.sender, self.peerlist)
            for peer in result:
                peer.last_ping = pong

        @staticmethod
        def _peer_filter(parent, peer):
            return peer in (parent.predecessor, parent.successor) or \
                   peer.hash in map(lambda p: p.hash,
                                    parent.routing_table.unique_iter(0))


    class PurgeThread(chutils.InfiniteThread):
        """ Periodically purges peers that haven't PING'd us in a while.
        """
        def __init__(self, peerlist, parent):
            super(HeartbeatManager.PurgeThread,
                  self).__init__(name="PurgeThread-%s" % str(int(parent.hash))[:4],
                                 pause=lambda: random.randint(15, 30))

            self.peerlist = peerlist
            self.parent = parent

        def _loop_method(self):
            to_remove = set()
            map(to_remove.add, filter(lambda x: not x.is_alive, self.peerlist))
            map(self.parent.remove_peer, to_remove)


    def __init__(self, peerlist, parent):
        self.ping_thread  = HeartbeatManager.PingThread(peerlist, parent)
        self.purge_thread = HeartbeatManager.PurgeThread(peerlist, parent)
        self.parent = parent

    def start(self):
        self.ping_thread.start()
        self.purge_thread.start()

    def join(self):
        self.ping_thread.join(100)
        self.purge_thread.join(100)

    def stop_running(self):
        self.ping_thread.stop_running()
        self.purge_thread.stop_running()

    def on_ping(self, sock, msg):
        """ Responds with a PONG message to an incoming PING.
        """
        ping = chordpkt.PingMessage.unpack(msg.data)
        L.info("Received a PING message %d, responding.", ping.value)
        pong = chordpkt.PongMessage.make_packet(self.parent.hash, ping.value,
                                                original=msg)
        try:
            self.parent.processor.response(sock, pong)
        except socket.error:
            p = self.parent._peerlist_contains(sock)
            if p: p.die()
