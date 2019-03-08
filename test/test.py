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

from scapy.all import *

packets = sniff(iface="en0", count=3)
for i in range(10):
    print(packets[i].show())
