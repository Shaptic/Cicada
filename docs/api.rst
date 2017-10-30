API Documentation
=================
This document contains detailed usage and tutorials of the *Cicada* API; it's
much more robust than what you can see under, say, ``help(swarmlib.swarmnode)``.


.. _swarmlib:

Interacting with *Cicada*: :py:class:`~swarmlib.SwarmPeer`
--------------------------------------------------------------------
This object is the main way of interacting with the *Cicada* API as it wraps the
lower-level DHT and routing details. It mimics the official ``socket.socket``
interface as closely as possible.

Unlike that interface, though, a ``bind`` is *required*, since every peer in the
swarm acts like a server for all the others.

.. py:module:: swarmlib
.. py:class::  SwarmPeer([hooks={}])

   This creates an object, registering a selection of callbacks that hook into
   various lower-level functionality. The valid keys into ``hooks`` are:

    - ``"send"``: called for every sent packet. it's called with the following signature: ``send(PeerSocket, bytes)``, where the :py:class:`PeerSocket` parameter is responsible for sending the data. this includes *all* messages, including the ones that occur at a lower level, such as the DHT layer.

    - ``"recv"``: called for every time a full high-level data packet is received. it's called with the following signature: ``recv(RemoteNode, bytes)``, where the :py:class:`RemoteNode` parameter is the node that the full data packet was received from.

    - ``"new_peer"``: called for every time a new :py:class:`SwarmPeer` joins the swarm: ``new_peer(PeerSocket)``.

.. py:method:: SwarmPeer.bind(addr, port[, external_ip=None, external_port=None])

   Binds to a particular address, establishing the listener for this member of a
   *Cicada* swarm. A subsequent :py:meth:`connect` indicates a peer joining an
   existing swarm, whereas a lack there-of indicates a peer establishing itself
   as the first member of a swarm. The optional parameters (which must *both* be
   specified) set a custom ID for the peer. **This is the first method that must
   be called on a** :py:class:`SwarmPeer` **instance, before any packet
   operations.**

   :param str addr: either the IP address of a local interface (such as ``eth0``), a hostname like ``localhost``, or an empty string, which would indicate a binding on *all* interfaces.
   :param int port: the port to bind on, in the range [1025, 65535)

   :param external_ip: the external IP address of your host on the network. this applies to NAT traversal situations as seen in the :ref:`example below <nat-example>` where you don't immediately have access to your external network or a port forwarded on your router. see the :py:mod:`traversal` module for details.
   :type external_ip: string or None

   :param external_port: as with the IP, this is the mapped external port.
   :type external_ip: int or None

   .. _nat-example:
   .. code-block:: python

       from cicada import swarmlib, traversal

       peer = swarmlib.SwarmPeer()
       with traversal.PortMapping(5000) as pm:
           eip = pm.mapper.external_ip
           peer.bind("192.168.0.100", pm.port, eip, pm.eport)

.. py:method:: SwarmPeer.connect(network_host, network_port[, timeout=10])

   Connects to a peer in an existing swarm.

   :param str network_host: the IP address or `FQDN <https://en.wikipedia.org/wiki/Fully_qualified_domain_name>`_ of an existing *Cicada* swarm.
   :param int network_port: similarly, the port of the listening peer
   :param int timeout: after this amount of time (in seconds), the call will immediately return.

.. py:method:: SwarmPeer.broadcast(data[, visited=[]])

   Broadcasts data to the entire swarm. For details on the broadcasting algorithm, you can read `this blog post <https://shaptic.github.io/networking/efficiently-broadcasting-in-a-peer-to-peer-network/>`_.

   :param bytes data: the raw data to sendtarget (tuple) – one of the following: a 2-tuple (hostname, port); a Hash; or another SwarmPeer instance
   :param list visited: this parameter is largely used internally to the :py:class:`~swarmnode.SwarmPeer` object to perform efficient broadcasting, but can be otherwise specified by the caller in order to indicate the specific peers that should be excluded from the broadcast. the list should contain :py:class:`~routing.Hash` objects.

.. py:method:: SwarmPeer.send(target, data[, duplicates=0])

   :param tuple target: one of the following: a 2-tuple (hostname, port); a :py:class:`~chordlib.routing.Hash`; or another :py:class:`~swarmnode.SwarmPeer` instance
   :param bytes data: the raw data to pack and send
   :param int duplicates: the amount of extra peers to route the message through; this is related to :ref:`attacker resilience <feature-resilience>`.

.. py:method:: SwarmPeer.recv()

   :rtype:  (:py:class:`~swarmnode.SwarmPeer`, bytes, bool)
   :return: the source peer that the message came from, the data message we received, and whether or not there are more messages pending


NAT Traversal Methods
---------------------
.. py:module:: traversal
.. py:class:: PortMapping(port[, protocol="tcp"])

   Establishes an external port mapping using the NAT traversal methods: UPnP, then NAT-PMP. It's intended to be used using Python's ``with`` construct. See :ref:`this example <nat-example>` for a use-case.

   If you wish to use one of the port mapping modules specifically, see the documentation for the :py:class:`~traversal.UPnP` or :py:class:`~traversal.NatPMP` objects.

   :param int port: this is the *requested* port to perform an external mapping on. if the port is already mapped, the ``with`` clause will exit immediately; see the :py:attr:`eport` attribute for the resulting port mapping.

.. py:attribute:: PortMapping.eport

   Specifies the external port that the mapping succeeded on; this may or may not be the initial port that was passed in.


Low-Level Interaction
---------------------


Routing
~~~~~~~
.. py:module:: chordlib.routing

These objects are used in various places to coordinate routing in the *Cicada* network, such as specifying a send target (instead of a raw address tuple).

.. py:class:: Hash([value="", hashed=""])

   Either you know the initial value and the hash is computed, or you know the hashed value (and its initial value is -- by definition -- not determinable) and only that is stored.


Custom Swarm Creation
~~~~~~~~~~~~~~~~~~~~~
.. py:module:: chordlib.localnode

.. topic:: Maintainer's Note

   The documentation in this area is much less frequently maintained, as its not
   intended for consumption. It's merely a starting point for anyone that isn't
   really interested in *Cicada* and more interested in creating their own DHTs.

This section outlines methods for creating custom swarms by interacting directly with the raw distributed hash table (DHT) objects. All of the objects outlined here *cannot join or otherwise interact with a Cicada swarm*, unless they understand the higher-level protocol's expectations.


.. py:class:: LocalNode(data, bind_addr[, hooks={}])

   Creates an unconnected peer in a Chord DHT.
