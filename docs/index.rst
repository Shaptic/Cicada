.. Cicada documentation master file, created by
   sphinx-quickstart on Thu Oct 26 01:39:31 2017.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

.. |br| raw:: html

   <br />

.. |travis| image:: https://travis-ci.org/Shaptic/Cicada.svg?branch=master
.. _travis: https://travis-ci.org/Shaptic/Cicada

.. |release| image:: https://img.shields.io/github/release/Shaptic/Cicada/all.svg
.. _release: https://github.com/Shaptic/Cicada/releases

Cicada Documentation
====================
*Cicada* is a resilient communication framework with peer-to-peer routing.

|travis|_ |release|_

Features:

- Lower bandwidth requirements for service providers
- Highly-efficient and resilient routing between users
- Safe & secure encryption among trusted peers
- Improved user performance

Installation
------------
There are a few minor dependencies that are easily ``pip``\ able; the biggest
requirement is that ``pygame`` is used in the visualization tools::

    $ pip install -r requirements.txt

If you want to build the documentation as well, install the
``full_requirements.txt``, which contains all of the Sphinx dependencies.

There are multiple ways of interacting with the *Cicada* library:

- The ``cicada.py`` script is a command-line interface for both creating a swarm
  and joining an existing swarm. You define a runtime configuration that
  executes commands in sequence. See the :doc:`runtime` documentation for
  details.
- The ``visualizer.py`` script is a visualizer that lets you arbitrarily connect
  a swarm of peers, watch them exchange messages, and stabilize. See the
  `Visualization section <#visualization>`_ for controls.
- The ``samples/`` directory holds a handful of applications for the library,
  one of which is a single-room chatting app.

.. topic:: \

    Unfortunately, the library is currently only available on Linux (and possible
    OS X) because of the dependencies I use for NAT traversal (specifically,
    `pynetinfo <https://github.com/sassanp/pynetinfo>`_). I'll be looking into a
    cross-platform solution soon.

Using Cicada in Your Application
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
*Cicada* comes with sample applications, but its up to you to use the library to
create a peer-to-peer application of your own. This could be a large variety of
decentralized applications, such as secure chat communcation, file-sharing, or
efficient mesh networking.

Advanced Features
-----------------
This section outlines advanced features that are or will be available in
*Cicada* in the official 1.0 release.

.. _feature-resilience:

Attacker Resilience
~~~~~~~~~~~~~~~~~~~
Traditionally, if a peer were to communicate with another peer, the traffic
would take a single route through the network topology to get to the other peer.
If there is a malicious agent in the network, they could rewrite unencrypted
traffic and inject arbitrary payloads. To work around this, traffic can be
forked and sent through multiple peers throughout the network simultaneously.
This increases overall load on the network, naturally, but is a small price to
pay in ensuring that your data isn't messed with in-transit.

To use this feature, pass the ``duplicates`` keyword argument on a *per-message*
basis when using the API:

.. code-block:: python

    peer = SwarmPeer("localhost", 10000)
    peer.connect("10.0.0.1", 50000)
    peer.send(("10.0.0.2", 50000), "hello!", duplicates=5)

Visualization
~~~~~~~~~~~~~
When running the *Cicada* visualization tool, ``visualizer.py``, there are a
number of controls for manipulating the behavior of the peers:

- Press **R** to join all peers together into a single network at random.
- Click a peer, press **J**, then click another peer in order to join the former to the latter.
- Pressing **L** between peers performs a lookup on the network on the latter's ID.
- Select a peer and press **F** to dump the peer's finger table.
- Select a peer and press **P** to dump its full list of known peers.
- Select a peer and press **B** to send a broadcast packet to the entire network that peer is connected to.

|

Feature Work
============
There is still a long way to go before *Cicada* has a robust enough feature set
for general consumption; this section outlines future plans.

Port Forwarding
---------------
Most people use devices on personal networks, and are thus hidden behind a
router that is doing **n**\ etwork **a**\ ddress **t**\ ranslation (NAT). Similar to
how BitTorrent needs to temporarily open ports in order to seed content, we need
to do likewise in order to facilitate new peers into the swarm through a local
peer. To do this, we use similar techniques to libtorrent, namely `NatPMP
<https://tools.ietf.org/html/rfc6886>`_ and `UPnP
<https://tools.ietf.org/html/rfc6970>`_. These will allow you to create a swarm
peer without worrying about whether or not it will be able to be accessed from
the Internet. |br| **Estimated Release**: 0.3.0-alpha

Security & Encryption
---------------------
In a peer-to-peer network, it's impossible to determine what peers your traffic
will travel through on the way to its destination. Standard routing through the
Internet faces these same implications, but we implicitly trust that network
topology more (we must, in fact, in order to gain any semblance of security).

The only way to *ensure* secure communications that are immune to
Man-in-the-Middle attacks and packet sniffing is to establish a trusted set of
encryption keys before using the network. This can be via secure email, and
encrypted telephone call, exchanging symmetric keys in person, etc. Once these
keys are exchanged, *Cicada* can use them directly to encrypt all outgoing
communication to a particular peer.

If you trust the network (or at least the majority of it -- see the
:ref:`feature-resilience` section), you can use standard public-key
authentication methods to establish an SSL communcation stream between
particular peers. That is to say, the traffic is still routed through the other
peers, but is encrypted with SSL. |br| **Estimated Release**: 1.0.0-rc

If you want to hard-code secret keys, configure a key file like so (choosing one
of either ``"peer"``, specifying the exact peer ID, or ``"address"``, specifying
the ``host:port`` pair of the peer):

.. code-block:: json

    {
      "trusted_hosts": [{
        "peer": "24355304810235874286134060455083535315455785472150272366747243996307578662525",
        "address": "75.23.66.101:7000",
        "outbound_key": "outbound_encryption_key",
        "inbound_key": "  inbound_encryption_key"
      }, {
      }]
    }

Then, just pass it to the command-line. Any communications between the localhost
and the peer at ``75.23.66.101:7000`` will be encrypted *if the other peer is also
aware of the encryption keys*:

.. code-block:: bash

    $ ./cicada.py -p 7001 --join 75.23.66.101:7000 --keys keylist.json


.. toctree::
   :hidden:
   :glob:

   *
