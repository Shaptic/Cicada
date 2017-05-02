#!/usr/bin/env python2
import time

from chord import localnode
from chord import chord

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

    print "main(%s, %s)" % (host_address, join_address)
    root = localnode.LocalChordNode("%s:%d" % host_address,
                                    bind_addr=host_address)

    if join_address is not None:
        root.join_ring(join_address)

    while True:
        time.sleep(15)
        print "root node:", root
        print "root fing:", root.fingers
        if join_address is not None:
            print "join node:", root.peers
            print "join fing:", root.peers[0].fingers

    return

    # Establish a list of independent nodes.
    ring = chord.main()
    print '\n'.join([ str(x) for x in ring ])
    print

    # We pick an arbitrary node to start the ring with: the first node.
    root = ring[0]
    print "Root:"
    print root
    print root.fingers
    print

    # We join a single node to the ring.
    try:
        first = ring[1]
        first.join_ring(root.local_addr)
        print "Joined %s to the ring." % first

        # What is the result?
        print "Root and its fingers"
        print root
        print root.fingers
        print "Joiner and its fingers"
        print first
        print first.fingers

    except Exception, e:
        import traceback
        import sys
        trace = traceback.format_exc(sys.exc_info())
        print trace

    finally:
        return ring

if __name__ == "__main__":
    import sys
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
