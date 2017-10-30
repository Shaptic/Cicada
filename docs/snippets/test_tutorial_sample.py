""" Acts as the first and second peer in a *local* Cicada swarm
(i.e. no external port mapping occurs).

This establishes an echoing swarm. The first peer is on port 5000,
and the second peer is on port 5001; pass "second" to the command
line to signify the second peer.
"""

import sys
import time

from cicada import swarmlib
from cicada.traversal import portmapper


target_port = 5001
local_port, second = 5000, False
if len(sys.argv) > 1 and sys.argv[1].lower() == "second":
  local_port += 1
  target_port -= 1
  second = True

local_address = portmapper.PortMapper.get_local_address()
peer = swarmlib.SwarmPeer()
peer.bind(local_address, local_port)
target = (local_address, target_port)

if second:  # second waits first, then echoes
  peer.connect(*target)

  while True:
    _, data, _ = peer.recv()
    print "Got an echo:", repr(data)
    peer.send(target, data[::-1])

else:
  while not peer.peers:
     time.sleep(1)  # wait for second peer to join

  peer.send(target, "hello!")

  while True:
    _, data, _ = peer.recv()
    print "Got an echo:", repr(data)
    peer.send(target, data[::-1])
