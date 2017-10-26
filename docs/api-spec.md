# API Specification #
This document contains detailed usage and tutorials of the _Cicada_ API; it's much more robust than what you can see under, say, `help(swarmlib.swarmnode)`.

## The `SwarmPeer` Object ##
This object is the main way of interacting with the _Cicada_ API as it wraps the lower-level DHT and routing details. It mimics the official `socket.socket` interface as closely as possible.

Unlike that interface, though, a `bind` is _required_, since every peer in the swarm acts like a server for all the others.
