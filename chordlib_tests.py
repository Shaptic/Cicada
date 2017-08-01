import packetlib.debug   as D
import packetlib.message as M

n = M.MessageContainer(M.MessageType.MSG_CH_NOTIFY, "hey babes\x77hey", 2884)
print n; print
print repr(n.pack()); print
n.dump()
print
D.dump_packet(n.pack(), n.full_format())


print "All tests passed!"
