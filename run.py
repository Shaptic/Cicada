#!/usr/bin/env python2
import sys
import time

import chordlib.localnode
import chordlib.utils as chutils
from   chordlib import L

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

    L.info("main(%s, %s)" % (host_address, join_address))
    root = chordlib.localnode.LocalNode("%s:%d" % host_address, host_address)

    if join_address is not None:
        root.join_ring(join_address)

    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        pass

    return (root, )

if __name__ == "__main__":
    client = None
    ip, port = sys.argv[1], sys.argv[2]
    if len(sys.argv) > 3:
        client = (sys.argv[3], int(sys.argv[4]))

    ring = main((ip, int(port)), client)
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

    # print
