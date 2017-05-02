"""
Cicada Protocol
===============

A distributed, server-less transfer protocol.

Author:  shaptic
Version: 0.1
"""

import threading
import socket
import select
import struct
import sys

import argparse
import uuid
import md5

import errors
import message
import channel
import debug

from debug import LoggedSocket as Socket

CICADA_PORT = 11052     # "cicada" as a hex port

class User(object):
    """ A User will host and join communication Channels.

    It is serializable, as channels need to know the user information contained
    within them (part of the JOIN process).
    """
    USER_ID_LENGTH = len(md5.md5("0").digest())
    RAW_FORMAT = [
        "H",    # 2-byte username length, LEN
        "%ds",  # LEN-byte readable username
        "%ds" % USER_ID_LENGTH,
                # Unique user ID, as an MD5 hash of the username and the
                # (IP address, source port) pairing.
    ]
    def __init__(self, name, user_id):
        self.username = name
        self.user_id = user_id

        self.hosted_channels = []
        self.joined_channels = []

    def pack(self):
        return struct.pack('!' + (''.join(self.RAW_FORMAT) % len(self.username)),
            len(self.username), self.username, self.user_id)

    @classmethod
    @debug.print_args
    def unpack(cls, packet):
        """ Extracts a User object from a raw bytestream.

        This differs from the full packet methods in the sense that it doesn't
        do any extra parsing around the bytestream. The assumption is that the
        entire `packet` object is the User object.
        """
        offset = 0
        getBlob = lambda i: message.CicadaMessage.extract_chunk(
            cls.RAW_FORMAT[i], packet, offset)

        user_len, offset = getBlob(0)
        user, offset     = message.CicadaMessage.extract_chunk(
            cls.RAW_FORMAT[1] % user_len, packet, offset)
        user_id, offset  = getBlob(2)

        j = User(user, user_id)
        return j

class AcceptThread(threading.Thread):
    def __init__(self, chan):
        super(AcceptThread, self).__init__(name="AcceptThread")
        self.chan = chan
        self.sock = chan.serve
        self.trigger = chan.new_user
        self.setDaemon(True)

    def run(self):
        client, addr = self.sock.accept()
        print "Connected to", addr
        self.trigger(client, addr)

class Channel(object):
    """ A Channel is a "room" of communicating Users.

    Specifically, this means all of these users are responsible for relaying
    messages amongst themselves when updates occur.

    The "creator" of a channel is simply the first user, who invites other to
    communicate with him via a external means (or an existing channel!). As
    people join the channel, each is assigned a particular set of users to which
    they are responsible for distributing data (the "neighbors").

    ## Communication
    Imagine a channel with 5 users: A-E, in which A created the channel
    initially. This is an imaginary configuration of the channel (not accurate,
    because of the connection algorithm below, but it's hard to represent in
    ASCII with too many users).

              A
             / \
            B---C
            |
            D---E

    This implies that when C sends a message to the channel, it will reach E
    through D and B. Everyone sees the message, they just all receive it in a
    different way.

    The number of connections between the users of the channel is actually
    optimized to be redundant in case of disconnects, but also not to grow
    quickly with the number of users, N. Specifically, each user is connected to
    log_2(N) other users. Thus, the above diagram is merely to demonstrate
    message pathing, not accurately represent the connections.

    ## Disconnects
    When a user disconnects from a channel, those that are directly connected
    to him are notified. They replace that user with someone else they've
    recently seen. If none have been seen (i.e. everyone is a direct contact),
    then they "ask for a reference" from one of their neighbors.
    """
    def __init__(self, name, fill_id=None):
        """ Creates a new channel, disconnected.

        The actual channel creator is not relevant, because of the design
        principle that all users are equal.
        """
        self.name = name        # readable channel name
        self.users = []         # users we communicate with, i.e. neighbors
        self.seen_users = []    # backup users, in case of disconnects

        self.id = channel.ChannelID(premade_id=fill_id)

    @debug.print_args
    def host(self, owner):
        """ Hosts this channel, waiting for users to connect.

        This should be called if this channel is hosted by the current user. To
        connect to a channel, use `join()`. Otherwise, this will begin a worker
        thread to await other users.

            This process is the same for channels that you join, as well, since
            anyone has a possible "insider" into the channel.

        For example, between A -- B -- C, a user D can connect through "invites"
        from any of these users.
        """
        self.owner = owner  # we track as many users as we can
        self.serve = Socket()
        self.serve.bind(("", CICADA_PORT))
        self.serve.listen(5)

        self._wait_thread()

    def new_user(self, cli, addr):
        """ Transforms a new socket into a user on this channel.

        This will await a JOIN message type, then respond accordingly.
        """
        print "Triggered accept event:", cli, addr

        data = cli.recv(message.CicadaMessage.MAX_SIZE)
        if not data:    # socket closed
            return False

        # TODO: Do something with the pre and post.
        obj, pr, ps = message.JoinMessage.unpack(data)
        if pr or ps: print "Wtf? pre='%s', post='%s'" % (repr(pr), repr(ps))

        if obj.channel_id == self.id:
            cli.sendall(self.createAck().pack())
        else:
            print >>sys.stderr, "Joiner matched the wrong channel ID."
            cli.sendall(self.createInvalidAck(obj).pack())
            return False

        print obj, repr(obj.from_user)
        self.users.append(User.unpack(obj.from_user))

    def join(self, owner, channel):
        """ Joins an existing channel.

        This replaces the internal tracking of the "owner."
        """
        if not isinstance(owner, User):
            raise TypeError("'owner' must be a User object.")

        if not isinstance(channel, Channel):
            raise TypeError("'channel' must be a Channel object.")

        if channel not in owner.hosted_channels:
            raise IndexError("%s is not hosted by user %s." % (owner, channel))

        self.owner = owner
        self.id = channel.id
        self.owner.send(message.JoinMessage(channel=channel))

    def createAck(self):
        return message.JoinAckMessage(self.id, self.name, 1, 1)

    def createInvalidAck(self, cause):
        return message.FailMessage(message.MessageType.MSG_JOIN_FAIL,
            "The channel ID does not match.", cause)

    def _wait_thread(self):
        self.thread = AcceptThread(self)
        self.thread.start()

    def __repr__(self): return str(self)
    def __str__(self):
        return "<Channel %s | %d/%d users>" % (
            self.display_name, len(self.users), len(self.seen_users))

@debug.print_args
def host(name, premade_id=None):
    # We are a particular user.
    me = User("halcyon", md5.md5("halcyon").digest())

    # We are hosting a channel.
    chan = Channel(name, fill_id=premade_id)

    # Spawn a thread to wait for someone to join the channel.
    chan.host(me)
    chan.thread.join()  # wait until the thread returns

    return

    # Create a user object and join it to a new channel.
    current_user = User("halcyon")
    chanA = Channel(name, current_user)
    chanA.id = channel.ChannelID(premade_id)
    current_user.hosted_channels.append(chanA)
    print chanA.id

    s = Socket()
    s.bind(('', CICADA_PORT))
    s.listen(10)

    sock, addr = s.accept()
    print "Connected to", addr

    data = sock.recv(1024)
    pkt, _, _ = message.JoinMessage.unpack(data)

    if str(pkt.id) == str(chanA.id):
        print "Joined!"
        ack = chanA.createAck()
    else:
        print "Absolutely not."
        ack = chanA.createInvalidAck(pkt)

    sock.sendall(ack.pack())

def join(addr, id):
    me = User("tester", md5.md5("tester").digest())
    msg = message.JoinMessage(channel.ChannelID(id), me.pack()).pack()
    print repr(msg)

    s = Socket()
    s.connect(addr)
    s.sendall(msg)
    data = s.recv(1024)
    pkt, _, _ = message.JoinAckMessage.unpack(data)
    print pkt
    s.close()

def main(args):
    if "--host" in args:
        i = args.index("--host")
        if len(args) <= i + 1:
            print >>sys.stderr, "No channel name found."
            return
        name = args[i + 1]

        host(name, args[i + 2] if len(args) > i + 2 else None)

    elif "--join" in args:
        i = args.index("--join")
        if len(args) <= i + 1:
            print >>sys.stderr, "No channel name found."
            return
        name = args[i + 1]

        join(("localhost", CICADA_PORT), name)

if __name__ == '__main__':
    print sys.argv[1:]
    main(sys.argv[1:])
