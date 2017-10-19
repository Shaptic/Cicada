#!/usr/bin/env python2
import pygame

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

