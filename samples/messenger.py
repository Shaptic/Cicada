#!/usr/bin/python2
""" Demonstrates a sample application that uses the Cicada swarm network.

This is a multi-user, channel-based, end-to-end encrypted chat application that
supports private messaging with a console-based UI.

The best way to use the interface is to have two open terminal windows, one for
reading, and one for writing. This prevents the input line from being
overwritten by incoming messages. Of course, there's support for using a single
window, but it will definitely be a less fluid experience.

Maybe someday I'll support ncurses for a nicer single-window UI, but don't count
on it. This is just a sample app, after all.
"""

# Inject the parent directory into the module search path.
import os
import sys

sys.path.append(os.path.abspath(".."))

import json
import random

# readline is a better interactive prompt
try:
    import readline
except ImportError:
    pass

import cicada
from   cicada.swarmlib.swarmnode import SwarmPeer
from   cicada.chordlib.utils     import InfiniteThread

def get_console_size():
    return map(int, os.popen('stty size', 'r').read().split())

def send_message(config, peer, sender, content, to=""):
    """ Broadcasts a packed message on the peer, unless it's a PM.
    """
    message = {
        "message": content,
        "sender":  sender,
        "to": to
    }
    if not to:
        peer.broadcast(json.dumps(message), duplicates=config.duplicates)
    else:
        raise NotImplementedError("can't PM yet")

def parse_message(raw):
    """ Parses a raw JSON string into a 3-tuple: (from, to, data).
    """
    raw = json.loads(raw)
    return raw["sender"], raw["to"], raw["message"]


class Config(object):
    """ Manages the command-line configuration.
    """
    def __init__(self):
        self.parser = argparse.ArgumentParser(description="")
        self.parser.add_argument("-r", "--resilience", dest="duplicates",
                                 default=0, type=int,
                                 help="")

        self.args = self.parser.parse_args()

    def __getattr__(self, attr):
        return getattr(self.args, attr)


class TextEntry(object):
    """ Represents the line on which the chat users enter their text.
    """
    def __init__(self, user):
        super(TextEntry, self).__init__()
        self.prefix = user.username
        self.input = ""

    def add_input(self, text):
        self.input = text

    def write(self):
        print "%s: %s" % (self.prefix, self.input),


class ReceiverThread(InfiniteThread):
    """ Receives data from the swarm in a blocking fashion.
    """
    def __init__(self, peer, output):
        super(ReceiverThread, self).__init__(pause=0.2)
        self.output_win = output
        self.peer = peer

    def _loop_method(self):
        more = True
        while more:
            peer, msg, more = self.peer.recv()
            src, dst, data  = parse_message(msg)
            self.output_win.writeln(data, src)


class User(object):
    """ Consolidates all of the user information.
    """
    def __init__(self, username):
        self.username = username
        self.channels = []

    def add_channel(self, channel):
        self.channels.append(channel)

    def part_channel(self, channel):
        try:    self.channels.remove(channel)
        except: pass


class Parser(object):
    """ Processes user input and performs action based on commands.
    """
    def __init__(self, host, window, user):
        super(Parser, self).__init__()
        self.config = Config()
        self.output = window
        self.quit = False
        self.host = host
        self.user = user

    def process(self, text):
        commands = [
            ("/connect ",   self._connect_handler),
            ("/join ",      self._join_handler),
            ("/part ",      self._join_handler),
            ("/help",       self._help_handler),
            ("/quit",       self._quit_handler),
            ("/stats",      self._stat_handler),
        ]

        if not text.strip(): return
        for cmd, fn in commands:
            if text.find(cmd) == 0:
                args = text[len(cmd):]
                self.output.writeln("Executing %s: %s" % (cmd.strip(), args))
                fn(args)
                return

        send_message(self.config, self.host, self.user.username, text)
        self.output.writeln(text, self.user.username)

    def _connect_handler(self, args):
        parts = args.split(":")
        if len(parts) != 2:
            self.output.writeln("/join expects host:port")
            return

        try:
            host, port = parts[0], int(parts[1])
        except ValueError:
            self.output.writeln("port wasn't an integer")
            return

        self.output.writeln("Joining %s:%d..." % (host, port))
        self.host.connect(host, port)
        self.output.writeln("Connected.")

    def _join_handler(self, args):
        pass

    def _part_handler(self, args):
        pass

    def _msg_handler(self, args):
        target, text = args.split(' ', 1)
        send_message(self.config, self.host, self.user.username, text,
                     channel="#general", to=target)


    def _stat_handler(self, args):
        self.output.writeln("Listening on %s:%d." % self.host.listener)
        self.output.writeln("Connected to %d peers in the swarm." % (
                            len(self.host.peers)))

    def _help_handler(self, args):
        self.output.writeln("/connect [server]: joins a new server")
        self.output.writeln("/join [channel]:   joins a channel on a server")
        self.output.writeln("/part [channel]:   leaves a channel on a server")
        self.output.writeln("/msg [username]:   private messages a user")
        self.output.writeln("/stats:            shows current swarm details")
        self.output.writeln("/help:             outputs this help text")
        self.output.writeln("/quit:             quits the application")

    def _quit_handler(self, args):
        self.output.writeln("Quitting.")
        self.quit = True


class OutputWindow(object):
    """ Represents all of the output from the user and other clients.
    """
    def __init__(self):
        super(OutputWindow, self).__init__()
        self.uname_off = len("long username | ")
        self.lines = []

    def writeln(self, line, username="***"):
        """ Draws a line of text, wrapping it to fit the screen.
        """
        _, console_w = get_console_size()
        useable_w = console_w - self.uname_off
        lines = []

        for i in xrange(0, len(line), useable_w):
            chunk = line[i : i + useable_w]
            lines.append(chunk)

        for line in lines:
            print "\r%s | %s" % (username.rjust(self.uname_off), line)


def main():
    username = raw_input("username: ")
    user = User(username)
    textinput = TextEntry(user)

    root = SwarmPeer({})
    root.bind("localhost", random.randint(5000, 60000))
    user.add_channel("#general")

    output_win = OutputWindow()
    parser = Parser(root, output_win, user)

    reader = ReceiverThread(root, output_win)
    reader.start()

    output_win.writeln("Bound on %s:%d" % root.listener)
    while not parser.quit:
        try:
            textinput.write()
            text = raw_input()
            parser.process(text)

        except KeyboardInterrupt:
            break

    reader.stop_running()
    reader.join(1)


if __name__ == '__main__':
    main()
