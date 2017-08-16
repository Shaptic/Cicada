#!/usr/bin/python2
""" A visual respresentation of a Chord system.
"""

import enum
import math
import random
import threading

import pygame

from chordlib import localnode
from chordlib import utils

# eventually eh
TOPOLOGY = """ {
    "peers": [
    ]
}
"""


class DrawState(enum.Enum):
    NORMAL    = 0x1
    SELECTED  = 0x2


class PeerState(enum.Enum):
    NORMAL   = 0x1


class Vector(object):
    """ A 2-dimensional position. """
    def __init__(self, x, y=None):
        if isinstance(x, tuple):
            self.x, self.y = x
        elif isinstance(x, Vector):
            self.x = x.x
            self.y = x.y
        elif isinstance(x, pygame.Surface):
            self.x = x.get_width()
            self.y = x.get_height()
        else:
            self.x = x
            self.y = y

    @property
    def w(self): return self.x

    @property
    def h(self): return self.y

    @property
    def t(self): return (self.x, self.y)

    @property
    def middle(self): return Vector(self.x / 2, self.y / 2)

    def __repr__(self): return "<%d, %d>" % self.t


class Window(object):
    WIDTH  = 1400
    HEIGHT = 1100

    def __init__(self):
        self.size = Vector(self.WIDTH, self.HEIGHT)
        self.screen = pygame.display.set_mode(self.size.t)
        pygame.display.set_caption("Cicada Simulator")

    def fill(self, color=(255, 255, 255)):
        self.screen.fill(color)

    def blit(self, sprite, pos):
        self.screen.blit(sprite, pos)

    @staticmethod
    def flip():
        pygame.display.flip()

    @property
    def center(self):
        return Vector(self.size.w / 2, self.size.h / 2)


class VisualSprite(pygame.sprite.Sprite):
    SPRITES = []
    def __init__(self, listener):
        super(VisualSprite, self).__init__()

        self.peer = VisualNode(self, listener)
        self.pos = Vector(0, 0)
        self._state = DrawState.NORMAL
        VisualSprite.SPRITES.append(self)
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
        circle_size = 50
        circle = pygame.Surface((circle_size, circle_size))
        circle.fill((255, 255, 255))
        line1 = FONT.render("hash=%d" % int(self.peer.hash),
                            True, (0, 0, 0))
        line2 = FONT.render("port=%d" % self.peer.chord_addr[1],
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
            ("state=%s" % self.peer.state),
            ("peers=%d" % len(self.peer.peers)),
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

    def select(self, prev=None):
        if self.state == DrawState.SELECTED:
            self.deselect()
        else:
            self.state = DrawState.SELECTED
            if prev:
                print "Joining %s to %s." % (prev.peer, self.peer)
                def func(): prev.peer.join_ring(self.peer.chord_addr)
                threading.Thread(target=func).start()

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
            if self.peer.predecessor or self.peer.successor:
                return (0, 190, 0)
            else:
                return (230, 230, 0)
        elif self.state == DrawState.SELECTED:
            return (0, 0, 200)
        return (255, 0, 0)

    def update(self, window):
        self.peer.update(window)


class VisualNode(localnode.LocalNode):
    """ Overloads peers to add visual indications of messages.
    """
    class DotState(enum.Enum):
        WAITING = 1
        CONFIRMED = 2

    class Dot(pygame.sprite.Sprite):
        def __init__(self, letter, color):
            super(VisualNode.Dot, self).__init__()
            self.image = pygame.Surface((24, 24))
            self.image.fill((255, 255, 255))
            pygame.draw.circle(self.image, color, (0, 0), 12)
            self.image.blit(FONT.render(letter, True, (255, 255, 255)), (0, 0))
            self.state = VisualNode.DotState.WAITING

        def move(self, x, y):
            self.pos = Vector(x, y)

        @property
        def rect(self):
            return pygame.Rect(self.pos.x, self.pos.y, 24, 24)

    def __init__(self, sprite, listener):
        super(VisualNode, self).__init__("%s:%d" % listener, listener)
        self.state = PeerState.NORMAL
        self.sprite = sprite
        self.dots = pygame.sprite.Group()

    def join_ring(self, remote):
        dot = VisualNode.Dot("J", (0, 0, 200))
        dot.move(*self.sprite.pos.t)
        # self.dots.add(dot)
        super(VisualNode, self).join_ring(remote)

    def update(self, window):
        for p in self.peers:
            sprite = None
            for match in VisualSprite.SPRITES:
                if p.chord_addr == match.peer.chord_addr:
                    sprite = match

            start = Vector(sprite.pos)
            start.x += 50; start.y += 25
            end = Vector(self.sprite.pos)
            end.x += 50; end.y += 25

            color, w = (0, 0, 0), 1
            if self.sprite.state == DrawState.SELECTED:
                color = self.sprite.color
                if p is self.successor: w = 4
                elif p is self.predecessor:
                    w = 4
                    color = (220, 0, 0)

            pygame.draw.line(window.screen, color, start.t, end.t, w)

        self.dots.draw(window.screen)


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

if __name__ == "__main__":
    pygame.init()

    FONT = pygame.font.SysFont("monospace", 24)

    quit = False
    clock = pygame.time.Clock()
    window = Window()
    ring = pygame.sprite.Group([
        VisualSprite(("localhost", 10000 + i)) for i in xrange(10)
    ])

    sprites = sorted(ring.sprites(), key=lambda x: int(x.peer.hash))
    dimension = min(window.size.w, window.size.h)
    radius = (dimension / 2) - (dimension * 0.10)
    for i, d in enumerate(xrange(0, 360, 360 / len(ring))):
        x = window.center.x + radius * math.cos(utils.rad(d))
        y = window.center.y + radius * math.sin(utils.rad(d))
        sprites[i].move(x, y)

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
                elif evt.key == pygame.K_j:
                    mode = Mode.JOINER
                elif evt.key in (pygame.K_ESCAPE, pygame.K_s):
                    mode = Mode.SELECT
                elif evt.key == pygame.K_p:
                    sel = get_selected(ring)
                    if not sel: continue
                    print "All of the peers in %s are:" % sel.peer
                    print "  s", sel.peer.successor
                    print "  p", sel.peer.predecessor
                    for p in sel.peer.peers:
                        if p not in (sel.peer.successor, sel.peer.predecessor):
                            print "  -", p

            elif evt.type == pygame.MOUSEMOTION:
                mouse_pos = Vector(*evt.pos)

            elif evt.type == pygame.MOUSEBUTTONDOWN:
                if evt.button == 1:
                    sel = None
                    if mode == Mode.JOINER:
                        sel = get_selected(ring)
                        for peer in ring: peer.deselect()
                        mode = Mode.SELECT

                    for peer in ring:
                        mouse = pygame.Rect(evt.pos[0], evt.pos[1], 1, 1)
                        if peer.rect.colliderect(mouse):
                            peer.select(sel)
                        else:
                            peer.deselect()

        for peer in ring:
            mouse = pygame.Rect(mouse_pos.x, mouse_pos.y, 1, 1)
            if mouse.colliderect(peer.rect):
                peer.on_hover(window, mouse.x, mouse.y)

        ring.update(window)
        window.flip()
        clock.tick(30)
