""" Implements an interactive shell for testing routing operations.
"""

import socket
import inspect

import chordlib
import chordlib.localnode
import cicada


DOCSTRING = """\
All addresses are expected to be a colon-separated pair specifying an IP or
hostname and a port. For example, localhost:1234.

create [address]
    Creates a Chord node listening on a particular address.

join [node] [address]
    On the provided [node], joins an existing Chord ring on the given address.

lookup [address]
    Performs a full route lookup on an address.

help, ?
    Shows this help text.

quit, q
    Exits the interactive shell.
"""


# Persistent nodes in the shell.
NODES = {}


def on_help():
    print DOCSTRING
    return True

def validate_address(addr):
    if addr.find(':') == -1:
        return False

    parts = addr.split(':')
    if len(parts) != 2:
        return False

    try:
        int(parts[1])
    except ValueError:
        return False

    return (parts[0], int(parts[1]))

def on_create(serve):
    address = validate_address(serve)
    if not address:
        print "Error when running command: create"
        print "Expected address in the format IP:port, got %s" % serve
        return

    print "Creating Chord node on %s:%d" % address
    host = chordlib.localnode.LocalNode("%s:%d" % address, address)
    NODES[int(host.hash)] = host
    print "Identifier: %d" % host.hash

def on_join(node, address):
    address = validate_address(address)
    if not address:
        print "Error when running command: join"
        print "Expected address in the format IP:port, got %s" % serve
        return

    for key in NODES:
        if str(key).startswith(node):
            root = NODES[key]
            break
    else:
        print "Error when running command: join"
        print "Failed to find node %d, valid nodes are %s" % (node, NODES.keys())
        return

    print "Joining Chord node on %s:%d" % address
    try:
        root.join_ring(address)
    except socket.error:
        print "Error when running command: join"
        print "Failed to join ring on address %s:%d" % address
        print "Are you sure there is a Chord ring at this address?"
        return

def on_lookup(address):
    return True

def parse(cmd, *args):
    if cmd in ('q', "quit"):
        return False

    if cmd not in COMMANDS:
        print "Invalid command: '%s'" % cmd
        print "Type 'help' or '?' for commands."
        return True

    fn = COMMANDS[cmd]
    details = inspect.getargspec(fn)
    if len(details.args) != len(args):
        print "Error when running command: '%s'" % cmd
        print "Expected %d parameters, got %d." % (len(details.args), len(args))
        return True

    fn(*args)
    return True

def sanitize(s):
    return s.strip().lower()

def shell():
    keep_going = True
    while keep_going:
        user_input = sanitize(raw_input(">>> "))
        parts = user_input.split(' ')
        keep_going = parse(*parts)

COMMANDS = {
    "?": on_help,
    "help": on_help,

    "join": on_join,
    "create": on_create,
    "lookup": on_lookup,
}


if __name__ == "__main__":
    shell()
