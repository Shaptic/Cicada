from collections import namedtuple
from chordlib.fingertable import FingerTable as FT

cn = namedtuple("ChordNode", "hash")
ft = FT(cn(1), 4)   # Create a 4-bit, 16-node ring.
assert str(ft) == """[ [2, 3) | None,
  [3, 5) | None,
  [5, 9) | None,
  [9, 1) | None ]"""

for _ in [ 3, 7, 0, 2 ]:
    ft.insert(cn(_))

assert str(ft) == """[ [2, 3) | ChordNode(hash=2),
  [3, 5) | ChordNode(hash=3),
  [5, 9) | ChordNode(hash=7),
  [9, 1) | ChordNode(hash=0) ]"""

ft.insert(cn(6))    # test regular distance
ft.insert(cn(14))   # test mod distance
ft.insert(cn(15))   # ensure no-op

assert str(ft) == """[ [2, 3) | ChordNode(hash=2),
  [3, 5) | ChordNode(hash=3),
  [5, 9) | ChordNode(hash=6),
  [9, 1) | ChordNode(hash=14) ]"""

print "All tests passed!"
