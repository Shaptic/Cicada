""" A visual respresentation of a Chord system.
"""

import random
import math

import pygame

from chordlib import localnode
from chordlib import utils

class VisualNode(localnode.LocalNode):
    def __init__(self, data):
        super(VisualNode, self).__init__(data)
        self.hashFont = pygame.font.SysFont("arial", 12)
        self.hashText = self.hashFont.render("%s" % str(self.hash)[:8], True, (0, 0, 0))
        self.entity   = pygame.Surface((16, 16))
        self.entity.fill((255, 0, 0))
        self._selected = False

    def place(self, x, y):
        self.position = (x, y)

    def draw(self, screen):
        screen.blit(self.entity, self.position)
        screen.blit(self.hashText, (
            self.position[0] + 4,
            self.position[1] + self.entity.get_height()))

    @property
    def selected(self):
        return self._selected

    @selected.setter
    def selected(self, state):
        if state:
            print "selected %s" % str(self)
            self.entity.fill((255, 255, 0))
        else:
            print "de-selected %s" % str(self)
            self.entity.fill((255, 0, 0))

def visuals(ring):
    SCREEN = (800, 800)
    CENTER = ((SCREEN[0] / 2) - 50, SCREEN[1] / 2)
    RADIUS = (SCREEN[0] / 2) - 50

    window = pygame.display.set_mode(SCREEN)
    window.fill((255, 255, 255))

    j = 0
    for i in xrange(0, 360, 360 / len(ring)):
        x = CENTER[0] + RADIUS * math.cos(utils.rad(i))
        y = CENTER[1] + RADIUS * math.sin(utils.rad(i))
        ring[j].place(x, y)
        j += 1

        print "(%.1f, %.1f)" % (x, y)

    selected_node = None

    quit = False
    while not quit:
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                quit = True
                break

            elif event.type == pygame.KEYDOWN and \
                 event.key == pygame.K_ESCAPE:

                selected_node = None
                for node in ring:
                    node.selected = False

            elif event.type == pygame.MOUSEBUTTONDOWN:
                rect = pygame.Rect(event.pos[0], event.pos[1], 1, 1)
                collider = None
                for node in ring:
                    comp_rect = node.entity.get_rect()
                    comp_rect.x = node.position[0]
                    comp_rect.y = node.position[1]
                    if comp_rect.colliderect(rect):
                        collider = node
                        break

                if collider and collider != selected_node:
                    if selected_node is None:
                        selected_node = collider
                        collider.selected = True

                    else:
                        import pdb; pdb.set_trace()
                        collider.joinRing(selected_node)

        window.fill((255, 255, 255))
        for dot in ring:
            dot.draw(window)

        if selected_node is not None:
            #
            # Draw a line to all of the entries in the finger table.
            #
            for finger in selected_node.fingers.entries:
                if finger.node is None:
                    continue

                pygame.draw.line(
                    window,
                    (255, 0, 0),
                    selected_node.position,
                    finger.node.position)

            #
            # Draw a line to the successor and predecessor.
            #
            if selected_node.successor is not None:
                pygame.draw.line(
                    window,
                    (255, 255, 0),
                    selected_node.position,
                    selected_node.successor.position)

            if selected_node.predecessor is not None:
                pygame.draw.line(
                    window,
                    (0, 0, 255),
                    selected_node.position,
                    selected_node.predecessor.position)

        pygame.display.flip()

if __name__ == "__main__":
    pygame.init()
    pygame.font.init()

    ring = [ VisualNode(str(_)) for _ in xrange(18) ]

    try:
        visuals(ring)

    except KeyboardInterrupt:
        print "Shutting down background stabilizer threads."
        for node in ring:
            node.stable.running = False

        for i, node in enumerate(ring):
            node.stable.join(500)
            print "Shut down %d/%d...\r" % (i + 1, len(ring)),

        print
