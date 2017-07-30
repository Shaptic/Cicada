from collections import namedtuple
from chordlib.routing import RoutingTable as RT

cn = namedtuple("ChordNode", "hash")
rt = RT(cn(1), 4)   # Create a 4-bit, 16-node ring.
assert str(rt) == """[ [2, 3) | None,
  [3, 5) | None,
  [5, 9) | None,
  [9, 1) | None ]"""

for _ in [ 3, 7, 0, 2 ]:
    rt.insert(cn(_))

assert str(rt) == """[ [2, 3) | ChordNode(hash=2),
  [3, 5) | ChordNode(hash=3),
  [5, 9) | ChordNode(hash=7),
  [9, 1) | ChordNode(hash=0) ]"""

rt.insert(cn(6))    # test regular distance
rt.insert(cn(14))   # test mod distance
rt.insert(cn(15))   # ensure no-op

assert str(rt) == """[ [2, 3) | ChordNode(hash=2),
  [3, 5) | ChordNode(hash=3),
  [5, 9) | ChordNode(hash=6),
  [9, 1) | ChordNode(hash=14) ]"""

print "All tests passed!"
