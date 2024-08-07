# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'demo.ui'
#
# Created by: PyQt5 UI code generator 5.11.3
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets

class UiMainWindow(object):
    def __init__(self, main_window):
        super(UiMainWindow, self).__init__()
        self.setup_ui(main_window)

    def setup_ui(self, main_window):
        main_window.setObjectName("main_window")
        main_window.resize(441, 452)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(main_window.sizePolicy().hasHeightForWidth())
        main_window.setSizePolicy(sizePolicy)
        main_window.setCursor(QtGui.QCursor(QtCore.Qt.ArrowCursor))
        self.centralwidget = QtWidgets.QWidget(main_window)
        self.centralwidget.setObjectName("centralwidget")
        self.switch_function = QtWidgets.QTabWidget(self.centralwidget)
        self.switch_function.setGeometry(QtCore.QRect(10, 10, 411, 401))
        self.switch_function.setObjectName("switch_function")
        self.arp_attack = QtWidgets.QWidget()
        self.arp_attack.setObjectName("arp_attack")
        self.button_find_host = QtWidgets.QPushButton(self.arp_attack)
        self.button_find_host.setGeometry(QtCore.QRect(20, 10, 111, 32))
        self.button_find_host.setObjectName("button_find_host")
        self.host_list = QtWidgets.QListWidget(self.arp_attack)
        self.host_list.setGeometry(QtCore.QRect(20, 40, 111, 291))
        self.host_list.setObjectName("host_list")
        self.target_ip = QtWidgets.QLineEdit(self.arp_attack)
        self.target_ip.setGeometry(QtCore.QRect(240, 110, 113, 21))
        self.target_ip.setObjectName("target_ip")
        self.target_mac = QtWidgets.QLineEdit(self.arp_attack)
        self.target_mac.setGeometry(QtCore.QRect(240, 140, 113, 21))
        self.target_mac.setObjectName("target_mac")
        self.pose_ip = QtWidgets.QLineEdit(self.arp_attack)
        self.pose_ip.setGeometry(QtCore.QRect(240, 170, 113, 21))
        self.pose_ip.setObjectName("pose_ip")
        self.pose_mac = QtWidgets.QLineEdit(self.arp_attack)
        self.pose_mac.setGeometry(QtCore.QRect(240, 200, 113, 21))
        self.pose_mac.setObjectName("pose_mac")
        self.button_interrupt_all = QtWidgets.QPushButton(self.arp_attack)
        self.button_interrupt_all.setGeometry(QtCore.QRect(10, 330, 131, 32))
        self.button_interrupt_all.setObjectName("button_interrupt_all")
        self.label_native_ip = QtWidgets.QLabel(self.arp_attack)
        self.label_native_ip.setGeometry(QtCore.QRect(150, 49, 60, 21))
        self.label_native_ip.setObjectName("label_native_ip")
        self.native_ip = QtWidgets.QLabel(self.arp_attack)
        self.native_ip.setGeometry(QtCore.QRect(240, 50, 111, 21))
        self.native_ip.setText("")
        self.native_ip.setObjectName("native_ip")
        self.label_native_mac = QtWidgets.QLabel(self.arp_attack)
        self.label_native_mac.setGeometry(QtCore.QRect(150, 80, 60, 21))
        self.label_native_mac.setObjectName("label_native_mac")
        self.native_mac = QtWidgets.QLabel(self.arp_attack)
        self.native_mac.setGeometry(QtCore.QRect(240, 80, 111, 21))
        self.native_mac.setText("")
        self.native_mac.setObjectName("native_mac")
        self.label_target_ip = QtWidgets.QLabel(self.arp_attack)
        self.label_target_ip.setGeometry(QtCore.QRect(150, 110, 71, 21))
        self.label_target_ip.setObjectName("label_target_ip")
        self.label_target_mac = QtWidgets.QLabel(self.arp_attack)
        self.label_target_mac.setGeometry(QtCore.QRect(150, 140, 91, 21))
        self.label_target_mac.setObjectName("label_target_mac")
        self.label_pose_ip = QtWidgets.QLabel(self.arp_attack)
        self.label_pose_ip.setGeometry(QtCore.QRect(150, 170, 71, 21))
        self.label_pose_ip.setObjectName("label_pose_ip")
        self.label_pose_mac = QtWidgets.QLabel(self.arp_attack)
        self.label_pose_mac.setGeometry(QtCore.QRect(150, 200, 91, 21))
        self.label_pose_mac.setObjectName("label_pose_mac")
        self.button_start_end = QtWidgets.QPushButton(self.arp_attack)
        self.button_start_end.setGeometry(QtCore.QRect(270, 330, 121, 32))
        self.button_start_end.setObjectName("button_start_end")
        self.mid_man_ip = QtWidgets.QLineEdit(self.arp_attack)
        self.mid_man_ip.setGeometry(QtCore.QRect(240, 230, 113, 21))
        self.mid_man_ip.setReadOnly(True)
        self.mid_man_ip.setClearButtonEnabled(False)
        self.mid_man_ip.setObjectName("mid_man_ip")
        self.mid_man_mac = QtWidgets.QLineEdit(self.arp_attack)
        self.mid_man_mac.setGeometry(QtCore.QRect(240, 260, 113, 21))
        self.mid_man_mac.setReadOnly(True)
        self.mid_man_mac.setObjectName("mid_man_mac")
        self.label_mid_man_ip = QtWidgets.QLabel(self.arp_attack)
        self.label_mid_man_ip.setGeometry(QtCore.QRect(150, 230, 60, 21))
        self.label_mid_man_ip.setObjectName("label_mid_man_ip")
        self.label_mid_man_mac = QtWidgets.QLabel(self.arp_attack)
        self.label_mid_man_mac.setGeometry(QtCore.QRect(150, 260, 81, 21))
        self.label_mid_man_mac.setObjectName("label_mid_man_mac")
        self.default_mid_man = QtWidgets.QCheckBox(self.arp_attack)
        self.default_mid_man.setGeometry(QtCore.QRect(210, 290, 141, 21))
        self.default_mid_man.setChecked(True)
        self.default_mid_man.setObjectName("default_mid_man")
        self.spoof_pattern = QtWidgets.QComboBox(self.arp_attack)
        self.spoof_pattern.setGeometry(QtCore.QRect(150, 10, 241, 31))
        self.spoof_pattern.setObjectName("spoof_pattern")
        self.switch_function.addTab(self.arp_attack, "")
        self.syn_flood_attack = QtWidgets.QWidget()
        self.syn_flood_attack.setObjectName("syn_flood_attack")
        self.label_target_ip_2 = QtWidgets.QLabel(self.syn_flood_attack)
        self.label_target_ip_2.setGeometry(QtCore.QRect(90, 50, 60, 21))
        self.label_target_ip_2.setObjectName("label_target_ip_2")
        self.label_target_port = QtWidgets.QLabel(self.syn_flood_attack)
        self.label_target_port.setGeometry(QtCore.QRect(90, 130, 60, 21))
        self.label_target_port.setObjectName("label_target_port")
        self.target_ip_2 = QtWidgets.QLineEdit(self.syn_flood_attack)
        self.target_ip_2.setGeometry(QtCore.QRect(210, 50, 111, 21))
        self.target_ip_2.setObjectName("target_ip_2")
        self.target_port = QtWidgets.QLineEdit(self.syn_flood_attack)
        self.target_port.setGeometry(QtCore.QRect(210, 130, 113, 21))
        self.target_port.setObjectName("target_port")
        self.label_threads = QtWidgets.QLabel(self.syn_flood_attack)
        self.label_threads.setGeometry(QtCore.QRect(90, 210, 60, 21))
        self.label_threads.setObjectName("label_threads")
        self.threads = QtWidgets.QComboBox(self.syn_flood_attack)
        self.threads.setGeometry(QtCore.QRect(210, 210, 111, 26))
        self.threads.setObjectName("threads")
        self.button_start_end_2 = QtWidgets.QPushButton(self.syn_flood_attack)
        self.button_start_end_2.setGeometry(QtCore.QRect(230, 290, 113, 21))
        self.button_start_end_2.setObjectName("button_start_end_2")
        self.label_logic_cpu_count = QtWidgets.QLabel(self.syn_flood_attack)
        self.label_logic_cpu_count.setGeometry(QtCore.QRect(70, 290, 91, 21))
        self.label_logic_cpu_count.setObjectName("label_logic_cpu_count")
        self.packet_count = QtWidgets.QLabel(self.syn_flood_attack)
        self.packet_count.setGeometry(QtCore.QRect(230, 330, 111, 21))
        self.packet_count.setText("")
        self.packet_count.setObjectName("packet_count")
        self.logic_cpu_count = QtWidgets.QLabel(self.syn_flood_attack)
        self.logic_cpu_count.setGeometry(QtCore.QRect(160, 290, 51, 21))
        self.logic_cpu_count.setText("")
        self.logic_cpu_count.setObjectName("logic_cpu_count")
        self.switch_function.addTab(self.syn_flood_attack, "")
        main_window.setCentralWidget(self.centralwidget)
        self.statusbar = QtWidgets.QStatusBar(main_window)
        self.statusbar.setObjectName("statusbar")
        main_window.setStatusBar(self.statusbar)

        self.retranslateUi(main_window)
        self.switch_function.setCurrentIndex(0)
        QtCore.QMetaObject.connectSlotsByName(main_window)

    def retranslateUi(self, main_window):
        _translate = QtCore.QCoreApplication.translate
        main_window.setWindowTitle(_translate("main_window", "攻击"))
        self.button_find_host.setText(_translate("main_window", "发现主机"))
        self.button_interrupt_all.setText(_translate("main_window", "中断所有主机网络"))
        self.label_native_ip.setText(_translate("main_window", "本机IP："))
        self.label_native_mac.setText(_translate("main_window", "本机Mac："))
        self.label_target_ip.setText(_translate("main_window", "攻击目标IP："))
        self.label_target_mac.setText(_translate("main_window", "攻击目标Mac："))
        self.label_pose_ip.setText(_translate("main_window", "伪装对象IP："))
        self.label_pose_mac.setText(_translate("main_window", "伪装对象Mac："))
        self.button_start_end.setText(_translate("main_window", "开始欺骗"))
        self.label_mid_man_ip.setText(_translate("main_window", "中间人IP："))
        self.label_mid_man_mac.setText(_translate("main_window", "中间人Mac："))
        self.default_mid_man.setText(_translate("main_window", "本机作为默认中间人"))
        self.switch_function.setTabText(self.switch_function.indexOf(self.arp_attack),
                                        _translate("main_window", "ARP欺骗"))
        self.label_target_ip_2.setText(_translate("main_window", "目标IP："))
        self.label_target_port.setText(_translate("main_window", "端口："))
        self.label_threads.setText(_translate("main_window", "线程数："))
        self.button_start_end_2.setText(_translate("main_window", "开始攻击"))
        self.label_logic_cpu_count.setText(_translate("main_window", "逻辑CPU个数："))
        self.switch_function.setTabText(self.switch_function.indexOf(self.syn_flood_attack),
                                        _translate("main_window", "SYN泛洪攻击"))
