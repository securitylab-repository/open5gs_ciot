from scapy.all import *

from scapy.all import IP
from scapy.utils import PcapReader

ip_map = {"192.168.1.152": "10.45.0.1", "1.2.3.5": "10.0.0.2"}
for p in PcapReader(".cap"):
    if IP not in p:
        continue
    p = p[IP]
    # if you want to use a constant map, only let the following line
    p.src = "10.0.0.1"
    p.dst = "10.0.0.2"
    # if you want to use the original src/dst if you don't find it in ip_map
    p.src = ip_map.get(p.src, p.src)
    p.dst = ip_map.get(p.dst, p.dst)
    # if you want to drop the packet if you don't find both src and dst in ip_map
    if p.src not in ip_map or p.dst not in ip_map:
        continue
    p.src = ip_map[p.src]
    p.dst = ip_map[p.dst]
    # 
    del(p.chksum)
    # then send the packet
    send(p)