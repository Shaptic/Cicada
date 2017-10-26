Runtime Interpreter
===================
By passing a file to ``cicada.py``, you can execute a series of commands that
interact with the *Cicada* API.

Each line is executed in order, and has a set of required parameters. Comment
lines start with a ``#`` and are ignored.

  - ``SEND [host] [port] [data...]``
    Sends a message to a particular address. ``[port]`` must be convertible to
    an integer.

  - ``RECV [count]``
    Waits for a message to be received from anyone. The ``[count]`` parameter is
    optional, and indicates the number of messages to wait for.

  - ``BCAST [data...]``
    Sends the specified data to the entire swarm.

  - ``OPT key1=value key2=value [key=value...]``
    Processes and sets the `configurable options <#configurable-options>`_. All
    subsequent lines will have these options applied to them.

  - ``WAIT [time (s)]``
    Waits for an incoming connection for a certain amount of time. If set to -1,
    waits indefinitely. This is useful for the first peer in a swarm.

Configurable Options
--------------------
==========  =======  ===========
Parameter   Type     Description
==========  =======  ===========
duplicates  ``int``  Configures the number of extra paths to take for all of the ``SEND`` calls.
==========  =======  ===========

Example Runtimes
----------------
You usually will want a single "server" runtime that starts the swarm; it waits
for the other peers to join. This can look something like this:

.. code-block:: none

    WAIT -1
    OPT duplicates=3
    BCAST Hey everyone, I'm the original peer.
    SEND localhost 49611 Hey there, specific client @ localhost:49611, it's me.
    RECV 2

You would run this like so::

    ./cicada.py --interface localhost -p 49610 --no-port-mapping first.conf

Similarly, you'd want a "join immediately" peers that look something like this:

.. code-block:: none

    RECV 1
    BCAST Hey everyone, I'm a new peer!
    RECV 1
    SEND localhost 49610 Hey there, localhost:49610; it's me.

This would be run like so::

    ./cicada.py --interface localhost -p 49611 --no-port-mapping --join localhost:49611 others.conf
