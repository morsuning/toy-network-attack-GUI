# import sys,getopt,socket
#
# def get_local_net():
#     #获取主机名
#     hostname = socket.gethostname()
#     #获取主机的局域网ip
#     localip = socket.gethostbyname(hostname)
#     localipnums = localip.split('.')
#     localipnums.pop()
#     localipnet = '.'.join(localipnums)
#     return localipnet
#
# def get_vlan_ip_and_mac():
#     localnet = get_local_net()
#     result = []
#     for ipFix in range(1,254):
#         ip =localnet+"."+str(ipFix)
#         #组合协议包
#         arpPkt=Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip)
#         res = srp1(arpPkt,timeout=1,verbose=0)
#         if res:
#             result.append({"localIP":res.psrc,"mac":res.hwsrc})
#     return result
#
# result = get_vlan_ip_and_mac()
#
# print(result)

import os

os.system('arp -a > ./test/temp.txt')
from attack.arp_attack import get_host_ip

host = get_host_ip()
with open('./test/temp.txt') as fp:
    for line in fp:
        print(line)
        import re

        line = re.findall(r'[(](.*?)[)]', line)
        print(line)
        line = line.split()[:2]

        if line and \
                line[0].startswith(host[:4]) and \
                (not line[0].endswith('255')):
            print(':'.join(line))
