import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('localhost', 4000))

print s.getsockname()
print s.getpeername()
s.sendall('byes')
