#!/usr/bin/env python2
import sys
import time
import logging
import argparse

from cicada import chordlib
from cicada import traversal
from cicada.chordlib  import log
from cicada.swarmlib  import swarmnode


class RuntimeFormatError(ValueError):
    pass


class RuntimeParser(object):
    """ Parses a runtime command file and executes it.

    == Specification ==

    Each line specifies a particular operation to be executed. These are
    executed sequentially. The commands, with their parameters, are:

        - SEND [host] [port] [data...]
          Sends a message to a particular address. [port] must be convertible to
          an integer.

        - RECV [count]
          Waits for a message to be received from anyone. The [count] parameter
          is optional, and indicates the number of messages to wait for.

        - BCAST [data...]
          Sends the specified data to the entire swarm.

        - OPT key1=value key2=value [key=value...]
          Processes and sets the configurable options. These can be seen in the
          `VALID_OPTS` class dictionary below. All subsequent lines will have
          these options applied to them.

        - WAIT [time (s)]
          Waits for an incoming connection for a certain amount of time. If set
          to -1, waits indefinitely. This is useful for the first peer in a
          swarm.

    You can also use the first character of each command as short-hand.

    TODO: Add PAUSE functionality, in order to let users respond to received
          messages during the execution.
    """
    VALID_OPTS = {
        "duplicates": int,
    }

    def __init__(self, filename):
        self.file = open(filename, "r")
        self.options = {
            "duplicates": 0
        }

    def run(self, peer):
        self.peer = peer
        for line in self.file.readlines():
            if not line.strip() or line.strip().startswith('#'): continue
            parts = line.split(' ')
            if len(parts) == 1:
                cmd, args = parts[0], ""
            else:
                cmd, args = line.split(' ', 1)
                args = args.strip()
            cmd = cmd.upper()

            print "Running", cmd
            if cmd in ("S", "SEND"):
                try:
                    args = args.split(' ', 2)
                    if len(args) <= 2:
                        raise ValueError()
                    target, data = (args[0], int(args[1])), args[2]

                except ValueError:
                     raise RuntimeFormatError("SEND requires: host port data")

                self._send(target, data, duplicates=self.options["duplicates"])
                print "done"

            elif cmd in ("R", "RECV"):
                try:
                    count = int(args)
                    self._recv(count)

                except ValueError, e:
                    print str(e)
                    raise RuntimeFormatError("RECV requires: count")

            elif cmd in ("O", "OPT"):
                for pair in args.split(' '):
                    k, v = pair.split('=')
                    if k not in self.VALID_OPTS:
                        raise RuntimeFormatError("OPT: invalid option '%s'" % k)

                    cast_v = self.VALID_OPTS[k](v)
                    print "Set %s = %s [%s]" % (k.lower(), repr(cast_v),
                          type(cast_v))
                    self.options[k.lower()] = cast_v

            elif cmd in ("B", "BCAST"):
                self._broadcast(args)

            elif cmd in ("W", "WAIT"):
                seconds = -1
                try:
                    if args.strip():
                        seconds = int(args)

                except ValueError:
                    raise RuntimeFormatError("WAIT: invalid time '%s'" % args)

                waited = 0
                print "Waiting for %d seconds for a connection." % seconds
                while seconds == -1 or waited < seconds:
                    if len(peer.peer.peers) > 0:
                        break
                    waited += 1
                    time.sleep(1)
                else:
                    raise RuntimeError("Peers didn't connect before timeout.")

            else:
                raise RuntimeFormatError("Invalid command: '%s'" % cmd)

    def _broadcast(self, data):
        print "Broadcasting %d bytes." % len(data)
        self.peer.broadcast(data, [])

    def _send(self, target, data, **kwargs):
        print "Sending %d bytes to %s:%d." % (len(data), target[0], target[1])
        self.peer.send(target, data, **kwargs)

    def _recv(self, count):
        for i in xrange(count):
            src, data, more = self.peer.recv()
            print "%d/%d -- %s:%d: %s" % (i + 1, count, src.chord_addr[0],
                  src.chord_addr[1], data)


def main(args):
    """ Runs an interactive Cicada session.
    """
    with traversal.PortMapping(args.port) as pm:
        if not pm or pm.port is False:
            print "Failed to map an external port. Try:"
            print "  - Open a port manually and pass it to --port, " + \
                  "then include --no-forwarding."
            print "  - Enabling NatPMP in your router, if applicable."
            print "  - Enabling UPnP in your router."
            return

        # if args.no_forwarding:
        ip = args.interface
        # else:
        #     ip = traversal.PortMapper.external_ip

        print "Binding %s:%d" % (ip, pm.port)
        peer = swarmnode.SwarmPeer({})
        peer.bind(ip, pm.port)
        if args.join:
            join_address = args.join.split(':')
            peer.connect(join_address[0], int(join_address[1]), args.timeout)

        rtp = RuntimeParser(args.runtime)
        rtp.run(peer)
        return peer


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Runs a partially-interactive sequence of commands on "
                    "a Cicada swarm.")

    parser.add_argument("runtime",
                        help="")
    parser.add_argument("--interface", metavar="IFACE", default="",
                        help="the interface to bind on")
    parser.add_argument("--port", metavar="N", default=0xC1CA, type=int,
                        help="the internal (and external!) port to listen on "
                             "(defaults to 0xC1CA, or 49610)")
    parser.add_argument("--no-forwarding", default=False, action="store_true",
                        help="don't attempt to perform an external mapping")
    parser.add_argument("--timeout", default=10, type=int,
                        help="the amount of time to wait while joining")
    parser.add_argument("--forwarding-attempts", default=5, type=int,
                        help="the number of ports to try for port mapping, "
                             "starting from the port passed in")
    parser.add_argument("--join", metavar="HOST:PORT",
                        help="joins an existing Cicada ring")
    parser.add_argument("--stdout", dest="screenlog", action="store_true",
                        help="write all logging output to stdout in addition "
                             "to the log file")
    parser.add_argument("--debug", dest="debuglog", action="store_true",
                        help="include DEBUG-level output in logging")
    args = parser.parse_args()

    if args.screenlog:
        h = logging.StreamHandler(sys.stdout)
        h.setFormatter(chordlib.ChordFormatter())
        chordlib.log.addHandler(h)

    if args.debuglog:
        chordlib.log.setLevel(logging.DEBUG)

    try:
        peer = main(args)
        print "Shutting down background stabilizer threads."
        peer.close()

    finally:
        print "Shut down."
