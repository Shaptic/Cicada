# Cicada #
A resilient communication framework with peer-to-peer routing.

Features:

  - Lower bandwidth requirements for service providers
  - Improved user performance
  - Highly-efficient and resilient routing between users
  - Safe & secure encryption among trusted peers

## Running ##
The `cicada` protocol has no external dependencies, just Python 2.7. Clone the
repository and start running a swarm:

    $ git clone https://github.com/shaptic/cicada.git
    $ cd cicada
    $ tail -f cicada.log
    $ python2 run.py localhost:10000 &
    $ python2 run.py localhost:10001 --join localhost:10000

You can also use the interactive shell to manage more complex swarms:

    $ python2 shell.py
    >>> create localhost:10000
    Creating Chord node on localhost:10000
    Identifier: 26490
    >>> create localhost:10001
    Creating Chord node on localhost:10001
    Identifier: 16966
    >>> create localhost:10002
    Creating Chord node on localhost:10002
    Identifier: 30572
    >>> join 169 264
    Joining Chord node on 127.0.0.1:10000
    >>> join 305 169
    Joining Chord node on 127.0.0.1:10001
    >>> show

### Using Cicada in Your Application ###
`cicada` in itself isn't an application in the sense that it doesn't really
_do_ anything. Of course, there are examples included for you to toy with to
see it in action (see `examples/`), but at its core it's merely a protocol for
you to take advantage of for your application.

## Advanced Features ##

### Security & Encryption ###
In a peer-to-peer network, it's impossible to determine what nodes your traffic
will travel through on the way to its destination. Standard routing through the
Internet faces these same implications, but we implicitly trust that network
topology more (we must, in fact, in order to gain any semblance of security).

The only way to _ensure_ secure communications that are immune to 
Man-in-the-Middle attacks and packet sniffing is to establish a trusted set of
encryption keys before using the network. This can be via secure email, and
encrypted telephone call, exchanging symmetric keys in person, etc. Once these
keys are exchanged, `cicada` can use them directly to encrypt all outgoing
communication to a particular node.

If you trust the network (or at least the majority of it -- see the [Attacker
Resilience](#attacker-resilience) section below), you can use standard public-
key authentication methods to establish an SSL communcation stream between
particular peers. That is to say, the traffic is still routed through the other
peers, but is encrypted with SSL.

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


### Attacker Resilience ###
Traditionally, if a peer were to communicate with another peer, the traffic
would take a single route through the network topology to get to the other
peer. If there is a malicious agent in the network, they could rewrite
unencrypted traffic and inject arbitrary payloads. To work around this, traffic
can be forked and sent through multiple nodes throughout the network
simultaneously. This increases overall load on the network, naturally, but is a
small price to pay in ensuring that your data isn't messed with in-transit.

To use this feature, just pass `--duplicate [number of duplicate paths]` to the
Cicada command-line, or pass the keyword argument `duplicates` to the
`CicadaNode` API object.

    $ cicada localhost:10000 --join 10.0.0.1:50000 --duplicate 3

This can further be customized on a _per-message_ basis (which obviously requires full API interaction):

    node = CicadaNode("localhost", 10000)
    node.connect("10.0.0.1", 50000)
    node.sendall("hello!", duplicates=5)

### Custom Routing ###
A single swarm node can be a part of _multiple swarms_, allowing it to act as a sort of "switch."
