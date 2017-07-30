""" An optimized routing table.

This is kind of a huge undertaking for later. It's a routing table that
compresses intervals until they're ready to be used. Thus, the intervals are
dynamically generated and shrunk as nodes join the ring. There are a ton of edge
cases and weird quirks to work out, hence why I'm not going to do this until
everything else is stabilized.

See `RoutingTable.insert` for some detailed explanations, as that's as far as I
got before realizing that this was a much bigger deal than it seemed.
"""


class RoutingTable(object):
    def __init__(self, node, bitcount=BITCOUNT):
        """ Initializes the finger table with 2^i intervals around the root.
        """
        self.local = Finger(0, self.mod - 1, node)
        self.mod = 2 ** bitcount
        self.root = node

        self.entries = {}
        self.intervals = [
            Finger(self._interval(i), self._interval(i + 1), None, self.mod) \
            for i in xrange(bitcount)
        ]

    def _interval(self, i):
        """ Calculates a finger table interval.
        """
        return (int(self.root.hash) + 2 ** i) % self.mod

    def insert(self, node):
        """ Sets a node for an interval if it's better than the existing one.

        We maintain an optimized finger table with only the required number of
        entries. The way finger table intervals are calculated is:

                start = n + 2^(i - 1)

        where `n` is root node hash, and `i` is the interval counter. The
        interval may wrap around the modulus boundary, so we need to be wary.

        So, for the first time we add a node, it manages the entire interval
        from [root + 1, root]. This is also the successor node. The second node
        is added only for its relevant range, which is from the first node to
        the second node, counter-clockwise through the hash ring. At the same
        time, the first node needs its interval adjusted to accomodate the new
        node, so there's no overlap.

        Let's work through an example to demonstrate this.

                                                  ___ 0 ___
                                                 /         \
            Mod = 8                             7           1
            maxlen(entries) = 3                /             \
            Root = Node_3                     6               2
                                               \             /
                                                5           3*
                                                 \___ 4 ___/

            The intervals in the finger table, via the formula above, are:

                3 + 2^0 = [4, 5)
                3 + 2^1 = [5, 7)
                3 + 2^2 = [7, 4)

            Suppose the first node to join is Node_1. Then, the entry table is
            simply:

                { 7: Interval([7, 7), Node_1) }

            How do we know a hash of 1 falls into the [7, 4) interval without
            storing the interval itself? Well, the node hash plus the root hash
            offset is 2^2 (exactly, but we can floor to the nearest power-of-two
            to get the same result for, say, Node_2). Then, the start of the 3rd
            interval can be implicitly calculated as above (7). We don't care
            about the end of the interval, since it's the only node, so every
            lookup results in Node_1.

            Now, we add another node, Node_4. Then, the entry table is
            calculated the same way:

                { 4: Interval([4, 7), Node_4),
                  7: Interval([7, 4), Node_1) }

            Because nextpow(4 + 3, 2) = 4, so the interval [4, ...), and the end
            is determined to be the next largest hash value. The [7, ...)
            interval is also adjusted (since it neighbors the new one) to stop
            at 4 to prevent overlaps.

            Now, another node, Node_0, which is _better_ for the interval [7, 4)
            than Node_1. The entry table becomes:

                { 4: Interval([4, 5), Node_4),
                  5: Interval([5, 4), Node_0) }

            Because, as before, nextpow(0 + 3, 2) = 2, so this belongs in the
            2nd interval, which doesn't exist yet: [3 + 2^1 = 5, ...). So we
            create a new interval as we did before, and after adjusting our
            neighboring intervals, we also see that we're a better match than
            our successor interval (Node_1 in [7, 4)), because we're closer to
            the start, so we _absorb_ the interval. If it was Node_6, instead,
            we'd stop at creating a new interval and have all 3 entries.

            A final case, which results in a no-op: adding Node_2.
            nextpow(2 + 3, 2) = 4, the third interval, [7, ...), but Node_0 is
            already better for that interval.

        The way we perform all of these lookups in practice is via binary search
        with predecessor and successor variations. So in the above example
        when we say "adjusting our neighboring intervals," that means a binary
        search for the predecessor and successor hash on the sorted set of
        dictionary keys:

            predecessor binary search of 0 in [ 4, 7 ], giving i=0, which is
            implied to be between 7 and 4 (since we were working in Mod 8), so
            we pull the last interval value, Interval([7, 4), Node_1).

            successor binary search of 0 in [ 4, 7 ], giving i=0, which is 4,
            and hence Interval([4, 7), Node_4).
        """
        h = int(node.hash)

        if not len(self.entries):
            self.entries[h] = node
            return

        k = sorted(self.entries.keys())

        # Find the predecessor of this node.
        i = search.bsearch(k, h, search.BSearchMode.PRED)
        predecessor = self.entries[k[i]]

        # Create the interval for this node, which is (pred.hash, node.hash]
        node_start = 2 * (predecessor.start - self.root.hash) + self.root.hash
        iv = Finger(node_start, h + 1, node=node, mod=self.mod)  # [start, end)

        # Inject this into the appropriate place of the finger table.
        self.entries[iv.start] = iv

        # Now, we need to adjust the _successor_ of this node so it doesn't
        # reach into our interval.
        i = search.bsearch(k, h, search.BSearchMode.SUCC)
        successor = self.entries[k[i]]
        successor.start = h + 1


def optimize_finger_table(fingers):
    """ Compresses a finger table by merging intervals with the same successor.

    TODO: Perform this optimization in-place? Is this even *necessary*?
          How do you insert things into it efficiently? Maybe use a hash-map
          of ranges? That is, { 1: node (implies [1, 5)), 5: node, ... }
    """
    if not fingers: return fingers

    merged = []
    maxlen = len(fingers) - 1

    inspect = fingers[0]
    merged_start = inspect.start
    merged_end = inspect.end

    for old in xrange(0, maxlen):
        if fingers[old + 1].node == inspect.node:
            merged_end = fingers[old + 1].end
        else:
            merged.append(Finger(merged_start, merged_end, inspect.node))
            inspect = fingers[old + 1]

    return merged
