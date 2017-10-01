#!/usr/bin/python2
from swarmlib.swarmnode import SwarmPeer

import pygame
from   pygame.locals import *
from   visualizer    import *


def main():
    quit = False
    w = Window()
    while not quit:
        for event in pygame.event.get():
            if event.type == QUIT: quit = True

        w.fill()
        w.flip()

if __name__ == '__main__':
    pygame.init()
    main()
