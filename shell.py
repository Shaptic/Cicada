""" Implements an interactive shell for testing routing operations.
"""

import socket
import inspect

import chordlib
import chordlib.localnode


DOCSTRING = """\
All addresses are expected to be a colon-separated pair specifying an IP or
hostname and a port. For example, localhost:1234.

create [address]
    Creates a Chord node listening on a particular address.

join [node] [address]
    On the provided [node], joins an existing Chord ring on the given address.

list, show
    Shows identifiers and a quick summary for all existing nodes.

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

def validate_address(addr, fname=""):
    def validator(addr):
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

    retval = validator(addr)
    if not retval:
        print "Error when running command%s" % (": %s" % fname if fname else "")
        print "Expected address in the format IP:port, got %s" % addr
        return False

    return retval

def validate_node(node):
    for key in NODES:
        if str(key).startswith(node):
            return NODES[key], key
    else:
        print "Error when running command: join"
        print "Failed to find node %s, valid nodes are %s" % (node, NODES.keys())
    return None

def on_list():
    for key, node in NODES.items():
        print "Node identifier:", key
        print "    Listening on: %s:%d" % node.local_addr
        print "    Connected peers:", len(node.peers)

def on_create(serve):
    address = validate_address(serve, fname="join")
    if not address: return

    print "Creating Chord node on %s:%d" % address
    try:
        host = chordlib.localnode.LocalNode("%s:%d" % address, address)
    except socket.error:
        print "Error when running command: create"
        print "Failed to create Chord node on %s:%d" % address
        print "Are you sure the address is available (try 'list')?"
        print "Are you sure have permissions to bind to this port?"
        print "    Ports 1-1024 are restricted to root."

    NODES[int(host.hash)] = host
    print "Identifier: %d" % host.hash

def on_stop(node):
    root, node = validate_node(node)
    if not root: return

    print "Removed node", node
    del NODES[node]
    del root

def on_join(node, address):
    address = validate_address(address, fname="join")
    if not address: return

    root, node = validate_node(node)
    if not root: return

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

    if not cmd: return True
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

    "list": on_list,
    "show": on_list,
    "join": on_join,
    "create": on_create,
    "lookup": on_lookup,
}


if __name__ == "__main__":
    shell()
