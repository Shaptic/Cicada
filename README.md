# Cicada #
A resilient communication framework with peer-to-peer routing.

[![Build Status](https://travis-ci.org/Shaptic/Cicada.svg?branch=master)](https://travis-ci.org/Shaptic/Cicada) [![GitHub (pre-)release](https://img.shields.io/github/release/Shaptic/Cicada/all.svg)](https://github.com/Shaptic/Cicada/releases)

Features:

  - Lower bandwidth requirements for service providers
  - Highly-efficient and resilient routing between users
  - Safe & secure encryption among trusted peers
  - Improved user performance

## Installation ##
There are a few minor dependencies that are easily `pip`able; the biggest requirement is that `pygame` is used in the visualization tools:

```bash
$ pip install -r requirements.txt
```

There are multiple ways of interacting with the _Cicada_ library:

  - The `cicada.py` script is a command-line interface for both creating a swarm and joining an existing swarm. You define a runtime configuration that executes commands in sequence. See `runtime.md` in the documentation folder for details.
  - The `visualizer.py` script is a visualizer that lets you arbitrarily connect a swarm of peers, watch them exchange messages, and stabilize. See the [Visualization section](#visualization) for controls.
  - The `samples/` directory holds a handful of applications for the library, one of which is a single-room chatting app.

> Unfortunately, the library is currently only available on Linux (and possible OS X, but this is also untested) because of the dependencies used for NAT traversal (specifically, [`pynetinfo`](https://github.com/sassanp/pynetinfo)). I'll be looking into a cross-platform solution soon.

### Using Cicada in Your Application ###
_Cicada_ comes with sample applications, but its up to you to use the library to create a peer-to-peer application of your own. This could be a large variety of decentralized applications, such as secure chat communcation, file-sharing, or efficient mesh networking.

## Advanced Features ##

### Attacker Resilience ###
Traditionally, if a peer were to communicate with another peer, the traffic would take a single route through the network topology to get to the other peer. If there is a malicious agent in the network, they could rewrite unencrypted traffic and inject arbitrary payloads. To work around this, traffic can be forked and sent through multiple peers throughout the network simultaneously. This increases overall load on the network, naturally, but is a small price to pay in ensuring that your data isn't messed with in-transit.

To use this feature, pass the `duplicates` keyword argument on a _per-message_ basis when using the API:

```python
peer = SwarmPeer("localhost", 10000)
peer.connect("10.0.0.1", 50000)
peer.send(("10.0.0.2", 50000), "hello!", duplicates=5)
```

## Visualization ##
When running the _Cicada_ visualization tool, `visualizer.py`, there are a number of controls for manipulating the behavior of the peers:

  - Press **R** to join all peers together into a single network at random.
  - Click a peer, press **J**, then click another peer in order to join the former to the latter.
  - Pressing **L** between peers performs a lookup on the network on the latter's ID.
  - Select a peer and press **F** to dump the peer's finger table.
  - Select a peer and press **P** to dump its full list of known peers.
  - Select a peer and press **B** to send a broadcast packet to the entire network that peer is connected to.

# Feature Work #
There is still a long way to go before _Cicada_ has a robust enough feature set for general consumption; this section outlines future plans. Subsections define larger feature sets, but in the short term:

  - [ ] Add arbitrary data to **all** _Chord_ message types, so that we can have a faster handshake for the data layer rather than forcing them to operate in the `LOOKUP` layer.
  - [ ] Vary stabilization and routing table timings based on swarm churn.
  - [ ] Consolidate the parameters to `cicada.py` to be a robust `--bind`.
  - [ ] Improve resilience to peers dropping.
  - [ ] Add proper per-peer logging so debugging isn't miserable.
  - [ ] Fix socket error handling, popping the sockets off the stream list.
  - [ ] Try breaking hash-chaining and write tests for it.
  - [ ] Decide on a license and add it.
  - [ ] Upgrade the library to Python 3.

## Port Forwarding ##
Most people use devices on personal networks, and are thus hidden behind a router that is doing **n**etwork **a**ddress **t**ranslation (NAT). Similar to how BitTorrent needs to temporarily open ports in order to seed content, we need to do likewise in order to facilitate new peers into the swarm through a local peer. To do this, we use similar techniques to libtorrent, namely [NatPMP](https://tools.ietf.org/html/rfc6886) and [UPnP](https://tools.ietf.org/html/rfc6970). These will allow you to create a swarm peer without worrying about whether or not it will be able to be accessed from the Internet.  
**Estimated Release**: 0.3.0-alpha

## Security & Encryption ##
In a peer-to-peer network, it's impossible to determine what peers your traffic will travel through on the way to its destination. Standard routing through the Internet faces these same implications, but we implicitly trust that network topology more (we must, in fact, in order to gain any semblance of security).

The only way to _ensure_ secure communications that are immune to Man-in-the-Middle attacks and packet sniffing is to establish a trusted set of encryption keys before using the network. This can be via secure email, and encrypted telephone call, exchanging symmetric keys in person, etc. Once these keys are exchanged, _Cicada_ can use them directly to encrypt all outgoing communication to a particular peer.

If you trust the network (or at least the majority of it -- see the [Attacker Resilience](#attacker-resilience) section), you can use standard public-key authentication methods to establish an SSL communcation stream between particular peers. That is to say, the traffic is still routed through the other peers, but is encrypted with SSL.  
**Estimated Release**: 1.0.0-rc

If you want to hard-code secret keys, configure a key file like so:

```json
{
  "trusted_hosts": [{
    "address": "75.23.66.101",
    "outbound_key": "supersecretencryptionkey",
    "inbound_key": "superduperencryptionkey"
  }, {
  }]
}
```

Then, just pass it to the command-line. Any communications between the localhost and the peer at `75.23.66.101` will be encrypted _if the other peer is also aware of the encryption keys_.

    $ ./cicada.py -p 10000 --join 75.23.66.101:50000 --keys keylist.json

