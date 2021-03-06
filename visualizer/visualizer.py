#!/usr/bin/env python2
""" A visual respresentation of a Chord system.
"""
import sys
sys.path.append(".")    # if run from cicada/
sys.path.append("..")   # if run from cicada/visualizer/

import enum
import math
import time
import random
import argparse
import threading
import functools

import pygame

from cicada          import packetlib
from cicada.swarmlib import swarmnode
from cicada.chordlib import localnode
from cicada.chordlib import utils

from window  import Window
from vmath   import Vector


class DrawState(enum.Enum):
    NORMAL   = 0x1
    SELECTED = 0x2


class VisualSprite(pygame.sprite.Sprite):
    SPRITES = []
    def __init__(self, listener):
        super(VisualSprite, self).__init__()

        VisualSprite.SPRITES.append(self)
        self.pos = Vector(0, 0)
        self._state = DrawState.NORMAL
        self.peer = VisualNode(self)
        self.peer.bind(*listener)
        self.build()

    def build(self):
        """ Builds the peer sprite.

                   +------+
                  /        \
                 |          |
                  \        /
                   +------+
                 port = 50000
                 hash = 12345
        """
        circle_size = 40
        radius = Vector(circle_size, circle_size)
        circle = pygame.Surface(radius.t)
        circle.fill((255, 255, 255))

        line1 = FONT2.render("hash=%s" % str(int(self.peer.hash))[:6],
                             True, (0, 0, 0))
        line2 = FONT2.render("port=%d" % self.peer.listener[1],
                             True, (0, 0, 0))

        padding = Vector(6, 6)
        fullsize = Vector(max(circle.get_width(), line1.get_width(),
                              line2.get_width()),
                          sum([x.get_height() for x in (circle, line1, line2)]))
        fullsize.x += padding.x
        fullsize.y += padding.y
        middle = Vector(circle).middle
        pygame.draw.circle(circle, self.color, middle.t, middle.x)
        self.image = pygame.Surface(fullsize.t)
        self.image.fill((255, 255, 255))
        self.image.blit(circle, (circle.get_width() / 2, padding.h / 2))
        self.image.blit(line1, (0, circle.get_height()))
        self.image.blit(line2, (0, circle.get_height() + line1.get_height()))

    def move(self, x, y):
        self.pos = Vector(x, y)

    def on_hover(self, window, x, y):
        lines = []
        for t in [
            ("peers=%d" % len(self.peer.peer.peers)),
        ]:
            lines.append(FONT.render(t, True, (0, 0, 0)))

        y_offset = 0
        self.hovertext = pygame.Surface((max([s.get_width() for s in lines]),
                                         sum([s.get_height() for s in lines])))
        self.hovertext.fill((255, 255, 211))
        for line in lines:
            self.hovertext.blit(line, (0, y_offset))
            y_offset += line.get_height()

        window.blit(self.hovertext, (x + 20, y))

    def deselect(self):
        self.state = DrawState.NORMAL

    def select(self, selmode=None, prev=None):
        if self.state == DrawState.SELECTED:
            self.deselect()
        else:
            self.state = DrawState.SELECTED
            if prev and selmode == Mode.JOINER:
                print "Joining %s to %s." % (prev.peer, self.peer)
                func = lambda: prev.peer.connect(*self.peer.listener)
                threading.Thread(target=func).start()

            elif prev and selmode == Mode.LOOKUP:
                print "Looking up %d from %d" % (self.peer.hash, prev.peer.hash)
                start = time.time()
                def lookup_response(start_time, result, msg):
                    if msg is None:
                        print "The resulting node is itself:", result

                    else:
                        print "Lookup result was %s, %d" % (result, msg.mapped)

                    total = time.time() - start_time
                    print "Lookup operation took %0.2fms." % (total * 1000)

                def do_lookup(start):
                    prev.peer.get_route(
                        self.peer.hash,
                        functools.partial(lookup_response, start))

                threading.Thread(target=functools.partial(do_lookup,
                                                          start)).start()

    @property
    def rect(self):
        return pygame.Rect(self.pos.x, self.pos.y, self.image.get_width(),
                           self.image.get_height())

    @property
    def state(self): return self._state

    @state.setter
    def state(self, new_state):
        self._state = new_state
        self.build()

    @property
    def color(self):
        if self.state == DrawState.NORMAL:
            if self.peer.peer.predecessor or self.peer.peer.successor:
                return (0, 190, 0)
            else:
                return (230, 230, 0)
        elif self.state == DrawState.SELECTED:
            return (0, 0, 200)
        return (255, 0, 0)

    def update(self, window):
        self.peer.update(window)


class OutputLog(pygame.sprite.Sprite):
    """ Represents a text box, triggered on hovering a parent sprite.
    """
    def __init__(self, parent):
        super(OutputLog, self).__init__()
        header = FONT2.render("message log:", True, (0, 0, 0))
        self.image = pygame.Surface((header.get_width(), header.get_height()))
        self.image.fill((255, 255, 200))
        self.image.blit(header, (0, 0))
        self.parent = parent
        self.pos = Vector(0, 50)

    def write(self, *lines):
        # Step 1: render each line individually.
        renders = []
        for line in lines:
            render = FONT2.render(line, True, (0, 0, 0))
            renders.append(render)

        # Step 2: create a surface that will fit all of the new lines.
        #         calculate the longest line, and the total height of the new
        #         lines.
        new_height = sum(map(lambda x: x.get_height(), renders))
        new_width  = max(self.rect.w,
                         max(map(lambda x: x.get_width(), renders)))

        # Step 3: if the log is taller than the screen, remove old lines until
        #         it fits, simulating scrolling. we guesstimate the height of a
        #         line (because monospace).
        #
        #         we determine the number of lines we need to remove, and
        #         recreate the old log, cutting out from the top this number of
        #         lines.
        line_height = FONT2.size("Q")[1]
        win_height = pygame.display.get_surface().get_height()
        cutout_px = (new_height + self.rect.h) - win_height
        if cutout_px > self.rect.h:
            raise ValueError("rendering the new lines takes more space "
                             "than the screen itself!")

        if cutout_px > 0:      # otherwise, we have enough space
            temp = pygame.Surface((new_height + (self.rect.h - cutout_px),
                                   new_width))
            temp.blit(self.image, (0, -cutout_px))
            self.image = temp

        new_height += self.rect.h
        new_image = pygame.Surface((new_width, new_height))

        # Step 4: draw the old log at the origin
        new_image.fill((255, 255, 200))
        new_image.blit(self.image, (0, 0))

        # Step 5: render each new line after the old log
        y_offset = self.rect.h
        for line in renders:
            new_image.blit(line, (0, y_offset))
            y_offset += line.get_height()

        self.image = new_image

    @property
    def rect(self):
        return pygame.Rect(self.pos.x, self.pos.y, self.image.get_width(),
                           self.image.get_height())

    def update(self, window):
        mouse_pos = pygame.mouse.get_pos()
        if self.parent.rect.colliderect(pygame.Rect(mouse_pos[0], mouse_pos[1],
                                                    1, 1)):
            window.blit(self.image, self.pos.t)


class VisualNode(swarmnode.SwarmPeer):
    """ Overloads peers to add visual indications of messages.

    We hook into the send and receive operations of all of the sockets for the
    peer:

        - sending requests: we create an outbound dot and move it towards the
                            target, storing the sequence number for later
                            association.

        - sending responses: we create an outbound dot towards the target that
                             deactivates automatically when it hits the target.
    """

    class Dot(pygame.sprite.Sprite):
        """ A visual representation of a message.

        It automatically deactivates when it collides with the target.

        :msg        a `MessageContainer` instance
        :dest       the `VisualSprite` that we originated from
        :dest       a `VisualSprite` that we're trying to collide with
        """
        def __init__(self, msg, src, dest):
            self.text = packetlib.message.MessageType.LOOKUP[msg.type][0]
            if msg.is_response: self.text += "r"

            self.msg = msg
            self.src = src
            self.dest = dest

            self.active = True
            self.pos = Vector(src.pos)
            self.pos.x += 40; self.pos.y += 20
            self.build()

            super(VisualNode.Dot, self).__init__()

        def build(self):
            """ Constructs the sprite contents.
            """
            text = FONT.render(self.text, True, (0, 0, 0))

            self.image = pygame.Surface((text.get_width(), 30))
            self.image.fill((255, 255, 0))
            self.image.blit(text, (0, 0))

        @property
        def rect(self):
            return pygame.Rect(self.pos.x, self.pos.y, 32, 32)

        def update(self):
            if not self.active: return
            delta  = pygame.math.Vector2(*self.dest.pos.t)
            delta += pygame.math.Vector2(40, 20)
            delta -= pygame.math.Vector2(*self.pos.t)
            delta.normalize_ip()
            delta *= 5

            self.pos.x += delta.x
            self.pos.y += delta.y

            if self.dest.rect.colliderect(self.rect):
                self.active = False

        @property
        def dest_addr(self):
            return self.dest.peer.chord_addr

        @staticmethod
        def from_bytes(src, peersock, bs):
            msg = packetlib.message.MessageContainer.unpack(bs)

            try:
                pkt = packetlib.chord.generic_unpacker(msg)
                src.log.write(repr(pkt))
            except:
                pass

            dest = VisualNode._resolve(peersock)
            if not dest: return None
            dot = VisualNode.Dot(msg, src.sprite, dest.sprite)
            src.dots.add(dot)
            return dot


    def __init__(self, sprite):
        super(VisualNode, self).__init__(hooks={
            "send": functools.partial(VisualNode.Dot.from_bytes, self),
            "new_peer": RuntimePatchHack.peer_association,
        })

        self.sprite = sprite
        self.dots = pygame.sprite.Group()
        self.log = OutputLog(self.sprite)

    def update(self, window):
        for p in self.peer.peers:
            sprite = filter(lambda x: x.peer.listener == p.chord_addr,
                            VisualSprite.SPRITES)[0]

            start = Vector(sprite.pos)
            start.x += 40; start.y += 20
            end = Vector(self.sprite.pos)
            end.x += 40; end.y += 20

            color, w = (0, 0, 0), 1

            if p in (self.peer.successor, self.peer.predecessor):
                color = self.sprite.color
                if self.sprite.state == DrawState.SELECTED:
                    w = 4

                if self.peer.successor == self.peer.predecessor:
                    color = (220, 0, 220)
                elif p is self.peer.predecessor:
                    color = (220, 0, 0)

            if p in self.peer.routing_table:
                color = (200, 200, 0)
                if self.sprite.state == DrawState.SELECTED:
                    w = 4

            pygame.draw.line(window.screen, color, start.t, end.t, w)

        self.dots.update()
        self.dots = pygame.sprite.Group(*filter(lambda x: x.active, self.dots))
        self.dots.draw(window.screen)
        # self.log.update(window)

    @staticmethod
    def _finder(addr):
        for sp in VisualSprite.SPRITES:
            chaddr = sp.peer.listener
            if chaddr[0] == addr[0] and chaddr[1] == addr[1]:
                return sp.peer

    @staticmethod
    def _resolve(peersock):
        node = None
        try:
            # Either the remote is a `chord_addr` (if it accepted the
            # connection) or the remote is the `sockname` of a peer in another
            # peer.
            remote = peersock.remote
            for sprite in VisualSprite.SPRITES:
                if sprite.peer.listener == remote:
                    return sprite.peer

                for peer in sprite.peer.peer.peers:
                    if peer.peer_sock.local == remote:
                        return sprite.peer

        except Exception, e:
            import traceback
            print "_resolve() failure:", str(e)
            traceback.print_exc()

        return node


def peer_at(peers, x, y):
    for peer in peers:
        if peer.rect.colliderect(pygame.Rect(x, y, 1, 1)):
            return peer
    return None

def get_selected(ring):
    sel = filter(lambda x: x.state == DrawState.SELECTED, ring)
    return sel[0] if sel else None


class Mode(enum.Enum):
    SELECT = 1
    JOINER = 2
    LOOKUP = 3

def fix_ring(window, ring):
    sprites = sorted(ring.sprites(), key=lambda x: int(x.peer.hash))
    dimension = min(window.size.w, window.size.h)
    radius = (dimension / 2) - (dimension * 0.05)
    degree = 0

    for i, d in enumerate(xrange(0, len(ring))):
        x = window.center.x + radius * math.cos(utils.rad(degree))
        y = window.center.y + radius * math.sin(utils.rad(degree))
        degree += 360 / len(ring)
        sprites[i].move(x, y)


class RuntimePatchHack(object):
    @staticmethod
    def peer_association(peer):
        print "Original:", peer


if __name__ == "__main__":
    pygame.init()

    FONT = pygame.font.SysFont("monospace",  28)
    FONT2 = pygame.font.SysFont("monospace", 20)

    quit = False
    clock = pygame.time.Clock()
    window = Window()

    def peer_association_callback(peer):
        """ Associate the receiving socket object with the visual node.

        The `peer` parameter is the address of the new remote endpoint. Thus, we
        have to first iterate over the ring, searching for the peer with the
        _local_ endpoint matching this address. This is the peer that needs a
        hook added.
        """
        if peer[1] in xrange(10000, 10000 + len(ring)):
            return

        for sprite in ring:
            node = sprite.peer.peer
            for remote in node.peers:
                sock = remote.peer_sock
                if sock.remote == peer:
                    wrapped = functools.partial(VisualNode.Dot.from_bytes,
                                                sprite.peer)
                    sock.hooks["send"] = wrapped

    RuntimePatchHack.peer_association = staticmethod(peer_association_callback)

    ring = pygame.sprite.Group([
        VisualSprite(("localhost", 10000 + i)) for i in xrange(10)
    ])
    fix_ring(window, ring)

    mode = Mode.SELECT
    mouse_pos = Vector(0, 0)
    while not quit:
        window.fill()
        ring.draw(window.screen)
        window.blit(FONT.render(repr(mode), True, (0, 0, 0)), (0, 0))

        for evt in pygame.event.get():
            if evt.type == pygame.QUIT:
                quit = True

            elif evt.type == pygame.KEYUP:
                if evt.key == pygame.K_q:
                    quit = True

                # Adds a new node to the ring.
                elif evt.key == pygame.K_a:
                    def add(sprite):
                        connected = map(lambda s: s.peer,
                                        filter(lambda s: s.peer.peers, ring))
                        root = random.choice(connected)
                        sprite.peer.connect(*root.listener)

                    latest = VisualSprite(("localhost", 10000 + len(ring)))
                    ring.add(latest)
                    fix_ring(window, ring)
                    threading.Thread(
                        target=functools.partial(add, latest)
                    ).start()

                # Join mode -- allows you to connect the selected peer to the
                # next clicked peer.
                elif evt.key == pygame.K_j:
                    mode = Mode.JOINER

                # Cancel special modes / force select mode.
                elif evt.key in (pygame.K_ESCAPE, pygame.K_s):
                    mode = Mode.SELECT

                # Perform a value lookup.
                elif evt.key == pygame.K_l:
                    mode = Mode.LOOKUP

                # Print out the connected peers of a peer.
                elif evt.key == pygame.K_p:
                    sel = get_selected(ring)
                    if not sel: continue
                    peer = sel.peer.peer
                    print "All of the peers in %s are:" % peer
                    print "  s", peer.successor
                    print "  p", peer.predecessor
                    for p in peer.peers:
                        if p not in (peer.successor, peer.predecessor):
                            print "  -", p

                # Print out the routing table of a peer.
                elif evt.key == pygame.K_f:
                    sel = get_selected(ring)
                    if not sel: continue
                    print "The routing table of %s is:" % sel.peer.peer
                    for route in sel.peer.peer.routing_table:
                        print "  -", route

                # Disconnect the selected node from the ring.
                elif evt.key == pygame.K_d:
                    def fixer():
                        sel.peer.disconnect()
                        listener = ring[i].peer.chord_addr
                        ring[i].peer = VisualNode(ring[i])
                        ring[i].peer.bind(*listener)
                        ring[i].build()

                    sel = get_selected(ring)
                    if not sel: continue
                    i = ring.index(sel)
                    print "Leaving %s[%d] from the ring." % (sel.peer, i)
                    threading.Thread(target=fixer).start()

                # Interconnect nodes randomly.
                elif evt.key == pygame.K_r:
                    peerlist = map(lambda x: x.peer, ring)
                    def connect_all():
                        connected = [random.choice(peerlist)]
                        unconnected = list(peerlist)
                        unconnected.remove(connected[0])

                        while unconnected:
                            peer = random.choice(unconnected)
                            root = random.choice(connected)

                            print "Joining peer %s to network via %s" % (peer, root)
                            unconnected.remove(peer)
                            peer.connect(*root.listener)
                            connected.append(peer)

                    conn_thread = threading.Thread(target=connect_all)
                    conn_thread.start()

                # Broadcasts a packet to every peer from some source peer.
                elif evt.key == pygame.K_b:
                    sel = get_selected(ring)
                    if not sel: break
                    def bcaster(sprite):
                        data = "broadcast data from %s:%d" % sel.peer.listener
                        print "Sending '%s'" % data
                        sprite.peer.broadcast(data)

                    fn = functools.partial(bcaster, sel)
                    threading.Thread(target=fn).start()

            elif evt.type == pygame.MOUSEMOTION:
                mouse_pos = Vector(*evt.pos)

            elif evt.type == pygame.MOUSEBUTTONDOWN:
                if evt.button == 1:
                    sel = None
                    prevmode = mode
                    if mode in (Mode.JOINER, Mode.LOOKUP):
                        sel = get_selected(ring)
                        for peer in ring: peer.deselect()
                        mode = Mode.SELECT

                    for peer in ring:
                        mouse = pygame.Rect(evt.pos[0], evt.pos[1], 1, 1)
                        if peer.rect.colliderect(mouse):
                            peer.select(selmode=prevmode, prev=sel)
                        else:
                            peer.deselect()

        peer = peer_at(ring, mouse_pos.x, mouse_pos.y)
        if peer: peer.on_hover(window, mouse_pos.x, mouse_pos.y)

        ring.update(window)
        window.flip()
        clock.tick(30)
