import sys
sys.path.append("..")

""" Establishes a *local* swarm, echoing a message between them.
"""
import sys, time
from cicada import swarmlib
from cicada.traversal import portmapper

local_address = portmapper.PortMapper.get_local_address()
first, second = swarmlib.SwarmPeer(), swarmlib.SwarmPeer()

first.bind(local_address, 5000)
second.bind(local_address, 5001)
second.connect(*first.listener)

first.send(second.listener, "hello!")
src, data, _ = second.recv()
assert data == "hello!"
assert src.chord_addr == first.listener

second.send(first.listener, data[::-1])
src, data, _ = first.recv()
assert data == "!olleh"
assert src.chord_addr == second.listener
