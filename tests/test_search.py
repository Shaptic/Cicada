#! /usr/bin/env python2
""" Tests the various searching algorithms in `chordlib`.
"""
import sys
sys.path.append('.')

import random
import collections
import unittest

from cicada.chordlib.search import *

class TestSearchUtilities(unittest.TestCase):
    def test_bsearch_single(self):
        array = [5]
        self.assertEqual(bsearch(array, 10, mode=BSearchMode.SUCC), 1)
        self.assertEqual(bsearch(array, 2, mode=BSearchMode.SUCC), 0)
        self.assertEqual(bsearch(array, 10, mode=BSearchMode.PRED), 0)
        self.assertEqual(bsearch(array, 2, mode=BSearchMode.PRED), 0)

    def test_bsearch_big(self):
        array = [ 2 * i for i in xrange(6) ]
        self.assertEqual(bsearch(array, 2), 1)
        self.assertEqual(bsearch(array, 2, mode=BSearchMode.PRED), 1)
        self.assertEqual(bsearch(array, 3), -1)
        self.assertEqual(bsearch(array, 3, mode=BSearchMode.PRED), 1)
        self.assertEqual(bsearch(array, 3, mode=BSearchMode.SUCC), 2)
        self.assertEqual(bsearch(array, 12, mode=BSearchMode.SUCC), 6)

    def test_bsearch_lambda(self):
        A = collections.namedtuple("A", "a")
        array = [ A(2 * i) for i in xrange(6) ]
        self.assertEqual(bsearch(array, 6, func=lambda x: x.a), 3)


class TestPivotUtils(unittest.TestCase):
    def test_sorted(self):
        a = [ 1, 2, 3, 4 ]
        self.assertEqual(find_pivot(a), 0)

    def test_reversed(self):
        a = [ 1, 2, 3, 4 ]
        a = a[::-1]
        self.assertEqual(find_pivot(a), 3)

    def test_odd_no_pivot(self):
        a = [ 5, 10, 15, 20, 0 ]
        self.assertEqual(find_pivot(a), 4)

    def test_odd_pivot(self):
        a = [ 10, 12, 4, 8, 9 ]
        self.assertEqual(find_pivot(a), 2)

    def test_random(self):
        def rotate(array, i):
            return array[-i:] + array[:-i]

        for _ in xrange(10):        # random rotated lists
            r = xrange(random.randint(10, 50))
            tester = set([ random.choice(range(0, 100)) for x in r ])
            tester = list(sorted(tester))
            # Choose a random rotation size
            rot = random.randint(0, len(tester) - 1)
            tester = rotate(tester, rot)
            self.assertEqual(find_pivot(tester), rot)


class TestInsertionUtils(unittest.TestCase):
    def test_insertion_point(self):
        hashes = [ 50, 68, 75, 99, 14, 28 ]
        results = [
            find_insertion_point(40,  45, hashes),
            find_insertion_point(49,  45, hashes),
            find_insertion_point(55,  45, hashes),
            find_insertion_point(100, 45, hashes),
            find_insertion_point(5,   45, hashes),
            find_insertion_point(15,  45, hashes)
        ]
        self.assertEqual(results, [6, 0, 1, 4, 4, 5])
        self.assertEqual(find_insertion_point(20, 40, [ 50 ]), 1)
        self.assertEqual(find_insertion_point(20, 40, [ 30 ]), 1)
        self.assertEqual(find_insertion_point(30, 40, [ 20 ]), 1)

if __name__ == '__main__':
    unittest.main()
