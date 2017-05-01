import select
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('', 4000))
s.listen(5)

done = False
clients = []
while not done:
    print "ready to wait"
    print "clients:", clients

    rd, _, _ = select.select([ s ], [], [], 20)
    if rd:
        client, addr = rd[0].accept()
        import pdb; pdb.set_trace()
        print addr
        print client.getsockname()
        print client.getpeername()
        clients.append(client)
