import socket
from hexdump import hexdump
# from scapy.all import *
from scapy.contrib.gtp import GTPHeader

maxMessageSize = 65507
UDP_IP = "127.0.0.25"
UDP_PORT = 2152

sock = socket.socket(socket.AF_INET, # Internet
                     socket.SOCK_DGRAM) # UDP
sock.bind((UDP_IP, UDP_PORT))

print("binding to ip %s port %d" % (UDP_IP, UDP_PORT))

while True:
    data, addr = sock.recvfrom(maxMessageSize) # buffer size is 65507 bytes
    # print("received",len(data)," bytes")
    # print(data.hex())
    # hexdump(data)
    GTPHeader(data).show()
    


