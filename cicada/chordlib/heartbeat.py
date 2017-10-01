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

    class InfoThread(chutils.InfiniteThread):
        """ Sends pings to who we care about: predecessor and successor.
        """
        def __init__(self, peerlist, parent):
            super(HeartbeatManager.InfoThread, self).__init__(
                name="InfoThread-%s" % str(int(parent.hash))[:4],
                pause=5)

            self.parent = parent
            self.peerlist = peerlist
            self.processor = self.parent.processor

        def _loop_method(self):
            fn = functools.partial(self._peer_filter, self.parent)
            for peer in filter(fn, self.peerlist):
                L.info("Sending an INFO message to %s:%d",
                       *peer.peer_sock.remote)

                msg = chordpkt.InfoRequest.make_packet()
                self.processor.request(peer.peer_sock, msg,
                                       self.parent.on_info_response,
                                       wait_time=0)

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
        self.info_thread  = HeartbeatManager.InfoThread(peerlist, parent)
        self.purge_thread = HeartbeatManager.PurgeThread(peerlist, parent)
        self.parent = parent

    def start(self):
        self.info_thread.start()
        self.purge_thread.start()

    def join(self, t=100):
        self.info_thread.join(t)
        self.purge_thread.join(t)

    def stop_running(self):
        self.info_thread.stop_running()
        self.purge_thread.stop_running()
