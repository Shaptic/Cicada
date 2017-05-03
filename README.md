# Cicada #
A resilient communication framework with peer-to-peer routing.

## Efficient Routing ##
Routing uses the
[Chord](https://pdos.csail.mit.edu/papers/chord:sigcomm01/chord_sigcomm.pdf)
protocol for efficient lookups. It arranges the peers in a "hash ring" and
allows each peer to maintain an optimized lookup table to find other peers.

## Communication Protocol ##
The Cicada protocol establishes a concept of a "Room" and its "Users." A Room
is simply a collection of Users; it's a means to allow a client to connect to
multiple Rooms and become a (unique) peer in each one.

**TODO**

## Security ##
Assuming that none of the peers are adversarial, the protocol supports end-to-
end encryption between peers using asymmetric cryptography. This prevents any
snooping on communication amongst peers. If peers _are_ adversarial, though,
secure communication is impossible unless there is direct communication; if any
peers communicate by routing through each other, it's impossible.

However, if you expect adversarial peers and have a means through which to 
distribute a secret key, the protocol will support that.

## Visual Component ##
Included is a network visualizer using Pygame that uses Cicada in order to
simulate swarm intelligence in a flock of birds. A standard p2p model in which
every bird talks to every other would cause too much network communication
under a significant "flock size;" Cicada allows this to work with thousands of
nodes.

### Chord ###
The `chord` module features a stripped-down implementation of the Chord
protocol.

The protocol is used in Cicada in order to traverse a selection of IP addresses
when communicating between two particular ones. In other words, all of the peers
in a network form a Chord ring; when two of those peers wish to communicate,
they use Chord's "lookup" algorithm to actually route the data.

#### Example ####
Suppose we have the following network of peers, arranged in a Chord hash ring:

            6 -- 7
           /      \
          4        1
           \      /
            3 -- 2

Now, `Peer 3` wants to talk to `Peer 7`. According to the Chord protocol, `Peer
3` will have the following finger table (that is, direct connections): `[ 4, 6,
1 ]`. In order to communicate with `7`, `Peer 3` performs a Chord lookup on
`7`. This gives us the peer we *do* know about that immediately precedes `7` --
in this case, `Peer 6`. `Peer 3` sends a message to `Peer 6` with intent to
`Peer 7`. `Peer 6` has a direct path to `Peer 7` in his *[triggered]* finger
table; he can relay the message directly.

**NOTE**: This is what's called _recursive routing_. The alternative is
      _iterative routing_, in which `Peer 6` responds to `Peer 3` with `Peer 7`
      address, rather than routing it.

#### Broadcasts ####
With this network, broadcast messages can be distrbuted _extremely_ fast and
with optimally minimal overhead. If every peer sends the messages to all of its
fingers (i.e. direct neighbors), the broadcast will be done with `O(log n)`
complexity across all nodes; this is a huge improvement over the standard
`O(n^2)` complexity inherent to P2P.

# Todo List #
- [x] Allow a Chord node to join a ring correctly.
- [ ] Let the Chord ring recover from a failed node.
- [x] Implement threading for stabilization routine.
- [x] Test threading with respect to concurrent joins. 
- [x] Design and implement remote nodes and rings.
- [ ] Implement underlying p2p socket protocol.
