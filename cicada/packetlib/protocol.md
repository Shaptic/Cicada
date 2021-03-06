Contains packet-layer descriptions of the _Cicada_ protocol.

# Protocol #
There are two main categories of message types: those belonging to the low-
level _Chord_ protocol, and those belonging to the higher-level _Cicada_
protocol which facilitates the organization of independent Chord rings and
nodes.

## Message Container Format ##
The messages in the Chord protocol use the constant identifier `0x6368` (`ch`)
whereas those in the Cicada protocol use `0x6369` (`ci`) in their message
headers.

The header format is as follows:

  - 2-byte  protocol identifier.
  - 2-byte  protocol version.
  - 2-byte  message type.
  - 1-byte  response flag.
  - 4-byte  sequence number to uniquely identify the message.
  - 16-byte checksum of the entire packet, excluding the checksum field
            itself, which is treated as zeroed-out.
  - 4-byte  payload length, `P`, which is excluding the header.
            a word-aligned packet (including payload).
  - 1-byte  indicator of whether this is a request, response, or error. We've
            already included the full message type earlier, but this is a
            quick way to identify it.

For responses and errors, there are additional fields:

  - 4-byte  sequence number *and*
  - 16-byte checksum of the message we're responding to.

The content is, naturally, a `P`-byte payload.

### Terminator ##
The message is word-aligned, so there is padding at the end before the
termination sequence.

  - 1-byte padding length, `Z`, which is the amount of padding needed to get
  - Z-byte padding of `NUL` bytes (`0x00`).
  - 3-byte message terminator, `0x474b04` (`GK[EoT byte]`).

In total, the minimum message size before padding is:
    2 + 2 + 2 + 4 + 16 + 4 + 1 + 0 + 1 + 3 = **35 bytes**.

Each message is either a request or a response. The response type constant is +1
to the request type for easy correlation.

### Chord Message Types ###
In Chord, we are concerned with the following message pairs:

  - **Join**        Sent on initialization by a new node (the invitee) to an
                    existing Chord ring, indicating a request to join.

    **Response**    Send by the inviter in response containing the address of
                    the successor node that follows the invitee.

  - **Notify**      After joining, a fresh node will notify other nodes about
                    its existence, in order to allow those nodes to update their
                    predecessors to point to this fresh node if need be.

    **Response**    An indication of whether or not the node has become this
                    node's new predecessor. If it has, the original node may set
                    it as its successor to create the optimal ring.

  - **Info**        This is a request to another node for all of its internal
                    state.

    **Response**    This is an info update representing a node in its entirety
                    to another. This includes the predecessor and successor
                    addresses and its local finger table.

    **Lookup**      This is the core of the protocol, which performs a lookup
                    for a particular peer address through the network either
                    recursively (default) or iteratively.

    **Response**    The peer information of the lookup result.

  - **Error**       This can be sent as a request for any reason (for which
                    there is no response needed) or as a response to any of the
                    above request types. Correlation between the request and
                    response are done by sequence number and checksum.

  - **Ping**        A simple "are you there?" message to maintain a connection.
                    If a response fails on this (within a reasonable amount of
                    time), it is assumed that the node is down and thus gone
                    from the ring.

    **Pong**        The response, a simple ACK, with the same code as the one
                    used in the Ping request to truly indicate that you got it.

## Cicada Message Types ##

**TODO**: In Cicada, we have a larger variety of messages.
