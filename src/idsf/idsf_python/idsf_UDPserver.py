import socket
from hexdump import hexdump
from scapy.all import ls,raw
from scapy.contrib.gtp import GTPHeader
import random

def AImodel_Detect_Abnormal(raw_packet):
    return random.randrange(2)

def idsf_nsmf_send_session_release(ss_context_id):
    return True

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
    gtp_packet = GTPHeader(data)
    # print("TEID",gtp_packet.teid)
    ss_context_ref = gtp_packet.teid
    ip_packet = gtp_packet.payload.payload

    ip_raw = raw(ip_packet)
    res = AImodel_Detect_Abnormal(ip_raw)

    if res:
        response = idsf_nsmf_send_session_release(ss_context_ref)




