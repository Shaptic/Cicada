#!/usr/bin/env python2
import sys
import time
import logging
import argparse

from cicada import chordlib
from cicada.chordlib import localnode as localnode
from cicada.chordlib import utils     as chutils

def main(host_address, join_address=None):
    """ Executes a normal Chord workflow.

    A single Chord node is chosen as the root of the ring. All other peers will
    join _through_ this ring (or other rings that exist within the ring).

    If executed within the same process, this is the flow that will occur if
    there is a single root and two joining peers:
        - A node A establishes itself as the root: it has a `listener` socket
          waiting for new connections on a separate thread T_a.
        - A node B connects to node A, sending it a JOIN request through its
          socker `joiner` (synchronously). This communication happens through
          `B.joiner`, resulting in a trigger in `A.T_a` on the socket
          `listener`.
        - A responds with RJOIN on its `listener`, which is received by B's
          joiner. A adds `peer` to its internal `A.peers` list.
        - Once B receives it, the joiner socket is added to B's peer list.

    At this point, B will communicate and receive updates from B via its peer
    socket, and vice-versa.
    """
    chordlib.log.info("main(%s, %s)" % (host_address, join_address))
    root = localnode.LocalNode("%s:%d" % host_address, host_address)

    if join_address is not None:
        root.join_ring(join_address)

    while True:
        time.sleep(60)

    return (root, )

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Interact with a Chord ring.",
        epilog="Addresses are expected to be colon-separated pairs of an "
               "IP address (or a hostname) and a port number. For example: "
               "localhost:1234 or 10.0.0.1:5678.")

    parser.add_argument("listener", metavar="address",
        help="the address to listen on for incoming Chord peers")
    parser.add_argument("--join", dest="join_address", metavar="address",
        help="the address of an existing Chord ring to join")
    parser.add_argument("--duplicate", dest="duplicates", metavar="N",
        help="the number of extra routes to take per-message "
             "[NOT IMPLEMENTED]")
    parser.add_argument("--stdout", dest="screenlog", action="store_true",
        help="write all logging output to stdout in addition to the logfile")
    parser.add_argument("--debug", dest="debuglog", action="store_true",
        help="include DEBUG-level output in logging")

    args = parser.parse_args()
    if args.listener.find(':') == -1:
        parser.error("Invalid address! Expected 'ip:port' for listener.")

    server = args.listener.split(':')
    server = (server[0], int(server[1]))

    client = None
    if args.join_address:
        if args.join_address.find(':') == -1:
            parser.error("Invalid address! Expected 'ip:port' for joiner.")

        client = args.join_address.split(':')
        client = (client[0], int(client[1]))

    if args.screenlog:
        h = logging.StreamHandler(sys.stdout)
        h.setFormatter(chordlib.ChordFormatter())
        chordlib.log.addHandler(h)

    if args.debuglog:
        chordlib.log.setLevel(logging.DEBUG)

    ring = main(server, join_address=client)
    time.sleep(60)

    print "Shutting down background stabilizer threads."
    for node in ring:
        node.stable.stop_running()
        node.dispatcher.stop_running()
        node.listen_thread.stop_running()

    for i, node in enumerate(ring):
        node.stable.join(5)
        node.dispatcher.join(5)
        node.listen_thread.join(5)
        print "Shut down %d/%d...\r" % (i + 1, len(ring)),
