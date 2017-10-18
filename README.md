# Cicada #
A resilient communication framework with peer-to-peer routing.

[![Build Status](https://travis-ci.org/Shaptic/Cicada.svg?branch=master)](https://travis-ci.org/Shaptic/Cicada) [![GitHub last commit](https://img.shields.io/github/last-commit/shaptic/cicada.svg)](https://github.com/Shaptic/Cicada/commits/master) [![GitHub (pre-)release](https://img.shields.io/github/release/Shaptic/Cicada/all.svg)](https://github.com/Shaptic/Cicada/releases)

Features:

  - Lower bandwidth requirements for service providers
  - Highly-efficient and resilient routing between users
  - Safe & secure encryption among trusted peers
  - Improved user performance

## Installation ##
There are almost no dependencies outside of an updated `enum` module, though `pygame` is required to use the visualization tools. There are multiple ways of interacting with the _Cicada_ library:

  - The `cicada.py` script is a command-line interface for both creating a swarm and joining an existing swarm. See the `--help` for details.
  - The `visualizer.py` script is a visualizer that lets you arbitrarily connect a swarm of peers, watch them exchange messages, and stabilize. See the [Visualizer section](#visualizer) for controls.
  - The `samples/` directory holds a handful of applications for the library, one of which is a single-room chat messenger.

### Using Cicada in Your Application ###
_Cicada_ comes with sample applications, but its up to you to use the library to create a peer-to-peer application of your own. This could be a large variety of decentralized applications, such as secure chat communcation, file-sharing, or efficient mesh networking.

## Advanced Features ##

### Attacker Resilience ###
Traditionally, if a peer were to communicate with another peer, the traffic would take a single route through the network topology to get to the other peer. If there is a malicious agent in the network, they could rewrite unencrypted traffic and inject arbitrary payloads. To work around this, traffic can be forked and sent through multiple peers throughout the network simultaneously. This increases overall load on the network, naturally, but is a small price to pay in ensuring that your data isn't messed with in-transit.

To use this feature, just pass `--duplicate [number of duplicate paths]` to the _Cicada_ command-line, or pass the keyword argument `duplicates` to the `SwarmPeer` API object.

    $ cicada localhost:10000 --join 10.0.0.1:50000 --duplicate 3

This can further be customized on a _per-message_ basis (which obviously requires full API interaction):

    peer = SwarmPeer("localhost", 10000)
    peer.connect("10.0.0.1", 50000)
    peer.send(("10.0.0.2", 50000), "hello!", duplicates=5)

## Visualization ##
When running the _Cicada_ visualization tool, `visualizer.py`, there are a number of controls for manipulating the behavior of the peers:

  - Press **R** to join all peers together into a single network at random.
  - Click a peer, press **J**, then click another peer in order to join the former to the latter.
  - Pressing **L** between peers performs a lookup on the network on the latter's ID.
  - Select a peer and press **F** to dump the peer's finger table.
  - Select a peer and press **P** to dump its full list of known peers.
  - Select a peer and press **B** to send a broadcast packet to the entire network that peer is connected to.

# Feature Work #
There is still a long way to go before _Cicada_ has a robust enough feature set for consumption. This section outlines future plans. In the short term:

  - [ ] Update the in-code comments to make sure everything is current.
  - [ ] Refactor the _Cicada_-layer protocol to have better packing, especially regarding the message types.
  - [ ] Refactor message queueing so it doesn't arbitrarily search for the suffix bytes, since that breaks when someone actually tries sending them as high-level data.
  - [ ] Add `ProtocolSpecifier` info to all of the `BaseMessage` child classes.
  - [ ] Decide on a license and add it.
  - [x] Convert the docstring tests to unit tests.
  - [ ] Write more unit tests.
  - [ ] Try breaking hash-chaining and write tests for it.
  - [ ] Upgrade the library to Python 3.

## Security & Encryption ##
In a peer-to-peer network, it's impossible to determine what peers your traffic will travel through on the way to its destination. Standard routing through the Internet faces these same implications, but we implicitly trust that network topology more (we must, in fact, in order to gain any semblance of security).

The only way to _ensure_ secure communications that are immune to Man-in-the-Middle attacks and packet sniffing is to establish a trusted set of encryption keys before using the network. This can be via secure email, and encrypted telephone call, exchanging symmetric keys in person, etc. Once these keys are exchanged, _Cicada_ can use them directly to encrypt all outgoing communication to a particular peer.

If you trust the network (or at least the majority of it -- see the [Attacker Resilience](#attacker-resilience) section below), you can use standard public-key authentication methods to establish an SSL communcation stream between particular peers. That is to say, the traffic is still routed through the other peers, but is encrypted with SSL.

    $ cat keylist.json
    { 
      "trusted_hosts": [{
        "address": "75.23.66.101",
        "outbound_key": "supersecretencryptionkey",
        "inbound_key": "superduperencryptionkey"
      },{
        // ...
      }]
    }
    $ cicada wlan0:10000 --join 10.0.0.1:50000 --keys keylist.json
