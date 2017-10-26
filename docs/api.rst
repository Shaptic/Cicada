API Documentation
=================
This document contains detailed usage and tutorials of the *Cicada* API; it's
much more robust than what you can see under, say, ``help(swarmlib.swarmnode)``.

The ``SwarmPeer`` Object
------------------------
This object is the main way of interacting with the *Cicada* API as it wraps the
lower-level DHT and routing details. It mimics the official ``socket.socket``
interface as closely as possible.

Unlike that interface, though, a ``bind`` is *required*, since every peer in the
swarm acts like a server for all the others.
