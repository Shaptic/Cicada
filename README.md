# Cicada #
An stripped-down implementation of the Chord protocol.

## Description ##
The protocol is used in Cicada in order to traverse a selection of IP addresses
when communicating between two particular ones. In other words, all of the peers
in a network form a Chord ring; when two of those peers wish to communicate,
they use Chord's "lookup" algorithm to actually route the data.

### Example ###
Suppose we have the following network of peers, arranged in a Chord ring:

            6 -- 7
           /      \
          4        1
           \      /
            3 -- 2

Now, `Peer 3` wants to talk to `Peer 7`. According to the Chord protocol, `Peer
3` will have the following finger table (that is, direct connections): 4, 6, 1.
In order to communicate with `7`, `Peer 3` performs a Chord lookup on `7`. This
gives us the peer we *do* know about that immediately precedes `7` -- in this
case, `Peer 6`. `Peer 3` sends a message to `Peer 6` with intent to `Peer 7`.
`Peer 6` has a direct path to `Peer 7` in his [triggered] finger table; he can
relay the message directly.

**NOTE**: This is what's called _recursive routing_. The alternative is
      _iterative routing_, in which `Peer 6` responds to `Peer 3` with `Peer 7`
      address, rather than routing it himself.

## Broadcasts ##
With this network, broadcast messages can be distrbuted _extremely_ fast and
with optimally minimal overhead. If every peer sends the messages to all of its
fingers (i.e. direct neighbors), the broadcast will be done with `O(log n)`
complexity across all nodes; this is a huge improvement over the standard
`O(n^2)` complexity inherent to P2P.

## Security ##
As seen in the example, if `Peer 6` forwards to `Peer 7`, it will see the
content of the message. This can be solved with asymmetric cryptography
established between `Peer 3` and `Peer 7`, but if `Peer 6` is involved with
forwarding (and even relaying address information, in the iterative case), he
can still inject data and form independent encryption with both parties. As a
result, this protocol should ideally be used in a trustworthy environment, or
only perform encrypted communication between direct peers (safe! no MitM), or
with established encryption (specifically, peer-specific secret keys)
beforehand.

## References ##
[Chord Paper](https://pdos.csail.mit.edu/papers/chord:sigcomm01/chord_sigcomm.pdf)  
[Chord Wikipedia](https://en.wikipedia.org/wiki/Chord_project)  
[Diffie-Hellman Keys](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange)  

## Todo List ##
- [x] Allow a Chord node to join a ring correctly.
- [ ] Let the Chord ring recover from a failed node.
- [x] Threading for stabilization routine.
- [ ] Design and implement remote nodes and rings.
- [ ] Implement underlying p2p socket protocol.
