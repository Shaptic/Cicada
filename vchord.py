import pygame
import chord

class Visual_ChordNode(ChordNode):
    def __init__(self, data):
        super(Visual_ChordNode, self).__init__(data)
        self.hashFont = pygame.font.SysFont("arial", 12)
        self.hashText = self.hashFont.render("%s" % str(self.hash)[:8], True, (0, 0, 0))
        self.entity   = pygame.Surface((16, 16))
        self.entity.fill((255, 0, 0))

    def place(self, x, y):
        self.position = (x, y)

    def draw(self, screen):
        screen.blit(self.entity, self.position)
        screen.blit(self.hashText, (
            self.position[0] + 4,
            self.position[1] + self.entity.get_height()))

def visuals(ring):
    pygame.init()
    pygame.font.init()

    SCREEN = (800, 800)
    CENTER = ((SCREEN[0] / 2) - 50, SCREEN[1] / 2)
    RADIUS = (SCREEN[0] / 2) - 50

    window = pygame.display.set_mode(SCREEN)
    window.fill((255, 255, 255))

    j = 0
    for i in xrange(0, 360, 360 / len(ring)):
        x = CENTER[0] + RADIUS * math.cos(rad(i))
        y = CENTER[1] + RADIUS * math.sin(rad(i))
        ring[j].place(x, y)
        j += 1

        print "(%.1f, %.1f)" % (x, y)

    quit = False
    while not quit:
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                quit = True
                break

        for dot in ring:
            dot.draw(window)

        for finger in ring[0].fingers.nodes:
            pygame.draw.line(window, (255, 0, 0), ring[0].position, finger.position)

        pygame.display.flip()

