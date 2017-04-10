#!/usr/bin/env python2
from chord import chord

def main():
    # Establish a list of independent nodes.
    ring = chord.main()
    print '\n'.join([ str(x) for x in ring ])
    print

    # We decide to begin the ring with the first node.
    root = ring[0]
    print "Root:"
    print root
    print root.fingers

    # Add nodes to the ring and ensure finger tables are accurate.
    # for i in xrange(1, 4):#len(ring)):
    #     print "Joining node to root:"
    #     print ring[i]
    #     print ring[i].fingers
    #     ring[i].joinRing(root)
    #     root.fixFingers()
    #     root.stabilize()
    #     ring[i].stabilize()

    print "Done"
    print root.fingers
    return ring

if __name__ == "__main__":
    ring = main()
    print "Shutting down background stabilizer threads."
    for node in ring:
        node.stable.running = False

    for i, node in enumerate(ring):
        node.stable.join(500)
        print "Shut down %d/%d...\r" % (i + 1, len(ring)),

    print
