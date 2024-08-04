# import scapy.all
# def ftpsniff(pkt):
#     dest = pkt.getlayer(IP).dst
#     raw = pkt.sprintf('%Raw.load%')
#     user = re.findall('(?i)USER (.*)', raw)
#     pswd = re.findall('(?i)PASS (.*)', raw)
#     if user:
#         print '[*] Detected FTP Login to ' + str(dest)
#         print '[+] Username: ' + str(user[0])
#     elif pswd:
#         print '[+] Password: ' + str(pswd[0])

# from scapy.all import *
#
# packets = sniff(iface="en0", count=3)
# for i in range(10):
#     print(packets[i].show())

# 获取所有网络设备名称
# import psutil
# print(list(psutil.net_if_addrs()))

import ipaddress

from scapy.all import srp, Ether, ARP

from attack.arp_attack import get_host_ip

net = ipaddress.ip_network(get_host_ip())
IpScan = str(net)
print(IpScan)
try:
    ans, unans = srp(Ether(dst="FF:FF:FF:FF:FF:FF") / ARP(pdst=IpScan), timeout=2)
except Exception as e:
    print(e)
else:
    for send, rcv in ans:
        ListMACAddr = rcv.sprintf("%Ether.src%---%ARP.psrc%")
        print(ListMACAddr)
