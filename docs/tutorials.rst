Tutorials
=========

.. contents:: Jump to a Tutorial
   :depth: 3
   :backlinks: none


NAT Traversal
-------------
This is used for peers behind a router, as is the case for most users. There are
two methods of external port mapping, and both are covered here. To see usage
of "catch-all" port mapping, just reference the :ref:`example <nat-example>` in
the API docs.

.. topic:: Note

   This example should not be necessary in a few iterations of the library. It's
   necessary now because detecting whether or not the peer is behind a router
   (and thus needs NAT traversal) is not implemented. Eventually, this part will
   happen automatically.

.. _upnp:

UPnP
~~~~
**U**\ niversal **P**\ lug a\ **n**\ d **P**\ lay is the first method used when
using the generic :py:class:`traversal.PortMapping` object.

The following example tries to map the local port 7777 to external port 8888,
increasing the mapped port up to 5 times on failures.

.. code-block:: python

    import sys
    from cicada.traversal import upnp

    LOCAL_PORT = 7777
    ATTEMPTS = 5

    mapper = upnp.UPnP()
    mapper.create()

    eport = 8888
    for i in xrange(ATTEMPTS):
        if mapper.add_port_mapping(LOCAL_PORT, eport, protocol="udp"):
            break

        if i == ATTEMPTS - 1: continue
        print "Failed to map %d <--> %d, trying %d." % (
              LOCAL_PORT, eport, eport + 1)
        eport += 1

    else:
        print "Failed to map %d after 5 attempts." % LOCAL_PORT
        sys.exit(1)

    print "Succeeded in mapping %d <--> %d." % (LOCAL_PORT, eport)
    mapper.delete_port_mapping(LOCAL_PORT, protocol="udp")
    mapper.cleanup()    # removes *all* mappings

NAT-PMP
~~~~~~~
This method is often used on Apple routers and is the backup method tried after
:ref:`upnp`. Using this method is actually *identical* to :ref:`upnp`, as the
API is designed to be identical. The only difference is that you should use the
:py:class:`traversal.NatPMP` instance instead.


Simple 2-Node Echo Server
-------------------------
In this sample, we'll create a 2-peer *Cicada* swarm and echo messages back and
forth between the peers.

.. include:: snippets/test_tutorial_sample.py
   :literal:

