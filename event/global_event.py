
from ui.demo import UiMainWindow
from PyQt5.QtCore import QObject
from event import event_arp_attack, event_icmp_attack, event_syn_flood_attack

# 负责初始化界面，绑定全局事件
class Event(UiMainWindow, QObject):
    # 在此初始化其他Event
    def __init__(self, main_window):
        super().__init__(main_window)
        self.global_event()
        # self.event_arp_attack = event_arp_attack.ArpAttack()
        # self.event_icmp_attack = event_icmp_attack.IcmpAttack()
        # self.event_syn_flood_attack = event_syn_flood_attack.SynFloodAttack()

    def global_event(self):
        pass
