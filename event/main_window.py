# -*- coding: utf-8 -*-

from multiprocessing import Process

from PyQt5 import QtGui
from PyQt5.QtCore import Qt, QPoint
from PyQt5.QtWidgets import QMenu, QAbstractItemView

from attack import arp_attack, syn_flood_attack
from ui.main_window import UiMainWindow


# 负责初始化界面，绑定全局事件
class Event(UiMainWindow):
    # 在此初始化其他Event
    def __init__(self, main_window):
        super().__init__(main_window)
        self.global_event()
        self.event_arp_attack()
        self.event_syn_flood_attack()

    def global_event(self):
        self.statusbar.showMessage("作者：Kaoso", 1000)

    def event_arp_attack(self):
        self.host_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.host_list.setSelectionMode(QAbstractItemView.SingleSelection)

        self.contextMenu = QMenu()
        self.action_target = self.contextMenu.addAction(u'作为攻击目标')
        self.action_pose = self.contextMenu.addAction(u'作为伪装对象')

        self.setup_arp_attack_connect()
        self.native_ip.setText(arp_attack.get_host_ip())
        self.native_mac.setText(arp_attack.get_mac_address())
        self.default_mid_man.setCheckState(Qt.Checked)
        self.mid_man_ip.setText(self.native_ip.text())
        self.mid_man_mac.setText(self.native_mac.text())

        self.spoof_pattern.addItem("双向欺骗")
        self.spoof_pattern.addItem("单向欺骗")
        self.spoof_mode = 0

    def setup_arp_attack_connect(self):
        self.default_mid_man.stateChanged.connect(self.default_mid_man_click)
        self.button_find_host.clicked.connect(self.button_find_host_click)
        self.host_list.customContextMenuRequested[QPoint].connect(self.host_list_click)
        self.action_target.triggered.connect(self.action_target_handler)
        self.action_pose.triggered.connect(self.action_pose_handler)
        self.spoof_pattern.activated[str].connect(self.deception_way)
        self.button_start_end.clicked.connect(self.button_start_click)
        self.button_interrupt_all.clicked.connect(self.button_interrupt_all_click)

    def button_start_click(self):
        self.proc = Process(target=arp_attack.arp_attack, args=(
            self.mid_man_ip.text(), self.mid_man_mac.text(), self.target_ip.text(), self.target_mac.text(),
            self.pose_ip.text(), self.pose_mac.text(),
            self.spoof_mode,))
        self.proc.daemon = True
        self.button_start_end.setText("停止欺骗")
        self.statusbar.showMessage("已经开始欺骗", 5000)
        self.button_start_end.clicked.disconnect()
        self.button_start_end.clicked.connect(self.button_end_click)
        self.proc.start()

    def button_interrupt_all_click(self):
        self.proc_2 = Process(target=arp_attack.arp_interrupt_all, args=(self.pose_ip.text(), self.mid_man_mac.text(),))
        self.proc_2.daemon = True
        self.button_interrupt_all.setText("停止攻击")
        self.statusbar.showMessage("已经使子网内全部主机网络异常", 5000)
        self.button_interrupt_all.clicked.disconnect()
        self.button_interrupt_all.clicked.connect(self.button_interrupt_end_click)
        self.proc_2.start()

    def button_end_click(self):
        self.proc.terminate()
        self.button_start_end.setText("开始欺骗")
        self.button_start_end.clicked.disconnect()
        self.button_start_end.clicked.connect(self.button_start_click)

    def button_interrupt_end_click(self):
        self.proc_2.terminate()
        self.button_interrupt_all.setText("中断所有主机网络")
        self.button_interrupt_all.clicked.disconnect()
        self.button_interrupt_all.clicked.connect(self.button_interrupt_all_click)

    def deception_way(self, text):
        if text == "双向欺骗":
            self.spoof_mode = 0
        if text == "单向欺骗":
            self.spoof_mode = 1

    def default_mid_man_click(self):
        if self.default_mid_man.checkState() == Qt.Checked:
            self.mid_man_ip.setText(self.native_ip.text())
            self.mid_man_mac.setText(self.native_mac.text())
        else:
            self.mid_man_ip.setText("")
            self.mid_man_mac.setText("")
            self.mid_man_ip.setReadOnly(False)
            self.mid_man_mac.setReadOnly(False)

    def button_find_host_click(self):
        # TODO 刷新列表项
        ip_mac_list = arp_attack.arp_scan(None)
        # pro_scan_host = Process(target=arp_attack.arp_scan, args=(ip_mac_list, ))
        # pro_scan_host.daemon = True
        # pro_scan_host.start()
        # pro_scan_host.join()
        for i in ip_mac_list:
            self.host_list.addItem(i[0] + "\n" + i[1])

    def host_list_click(self):
        self.contextMenu.move(QtGui.QCursor().pos())
        self.contextMenu.show()

    def action_target_handler(self):
        ip = str(self.host_list.item(self.host_list.currentRow()).text()).split("\n")[0]
        mac = str(self.host_list.item(self.host_list.currentRow()).text()).split("\n")[1]
        self.target_ip.setText(ip)
        self.target_mac.setText(mac)

    def action_pose_handler(self):
        ip = str(self.host_list.item(self.host_list.currentRow()).text()).split("\n")[0]
        mac = str(self.host_list.item(self.host_list.currentRow()).text()).split("\n")[1]
        self.pose_ip.setText(ip)
        self.pose_mac.setText(mac)

    def event_syn_flood_attack(self):
        self.logic_cpu_count.setText(str(syn_flood_attack.cpu_count()))
        self.threads.addItem("1")
        self.threads.addItem("2")
        self.threads.addItem("4")
        self.threads.addItem("8")
        self.threads.addItem("16")
        self.button_start_end_2.clicked.connect(self.button_start_2)
        self.threads.activated[str].connect(self.cpu_core)

    def button_start_2(self):
        if self.target_ip_2.text() == "":
            self.statusbar.showMessage("请输入目标IP", 5000)
        if self.target_port.text() == "":
            self.statusbar.showMessage("请输入目标端口", 5000)
        # self.pool = Pool(self.cpu_core)
        # for i in range(self.cpu_core):
        #     self.pool.apply_async(syn_flood_attack.attack, )
        self.proc_3 = Process(target=syn_flood_attack.attack, args=(self.target_ip_2.text(), self.target_port.text(),))
        self.proc_3.daemon = True
        self.button_start_end_2.setText("停止攻击")
        self.statusbar.showMessage("正在攻击", 5000)
        self.button_start_end_2.clicked.disconnect()
        self.button_start_end_2.clicked.connect(self.button_end_click_2)
        self.proc_3.start()

    def button_end_click_2(self):
        self.proc_3.terminate()
        self.button_start_end_2.setText("开始攻击")
        self.button_start_end_2.clicked.disconnect()
        self.button_start_end_2.clicked.connect(self.button_start_2)

    def cpu_core(self, text):
        self.cpu_core = int(text)
