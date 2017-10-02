#!/usr/bin/env python2
import pygame
import visualizer.math

class Window(object):
    WIDTH  = 800
    HEIGHT = 600

    def __init__(self):
        self.size = visualizer.math.Vector(self.WIDTH, self.HEIGHT)
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
        return visualizer.math.Vector(self.size.w / 2, self.size.h / 2)
