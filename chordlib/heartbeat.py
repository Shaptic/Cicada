#!/usr/bin/python2

import random
from   chordlib  import commlib, L
from   packetlib import chord   as chordpkt
from   packetlib import message


class HeartbeatManager(object):
    """ Maintains connections between peers.
    """

    class PingThread(commlib.InfiniteThread):
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
            fn = lambda x: x in (self.parent.predecessor, self.parent.successor)
            for peer in filter(fn, self.peerlist):
                ping = chordpkt.PingMessage(self.parent.hash)
                msg = message.MessageContainer(ping.TYPE, data=ping.pack())

                L.info("Sending a PING with message %d.", ping.value)
                handlr = lambda s, m: self.on_pong(ping.value, s, m)
                self.processor.request(peer.peer_sock, msg, handlr, wait_time=0)

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


    class PurgeThread(commlib.InfiniteThread):
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
            if to_remove:
                from pprint import pprint
                import time
                print "Timed out peers:"
                for item in to_remove:
                    print item
                    print time.time()
                    print item.last_ping.time
                    print

            map(self.parent.remove_peer, to_remove)


    def __init__(self, peerlist, parent):
        self.ping_thread  = HeartbeatManager.PingThread(peerlist, parent)
        self.purge_thread = HeartbeatManager.PurgeThread(peerlist, parent)
        self.parent = parent

    def start(self):
        self.ping_thread.start()
        self.purge_thread.start()

    def stop_running(self):
        self.ping_thread.stop_running()
        self.purge_thread.stop_running()

    def on_ping(self, socket, msg):
        """ Responds with a PONG message to an incoming PING.
        """
        ping = chordpkt.PingMessage.unpack(msg.data)
        L.info("Received a PING message %d, responding.", ping.value)
        pong = chordpkt.PongMessage.make_packet(self.parent.hash, ping.value,
                                                original=msg)
        self.parent.processor.response(socket, pong)
