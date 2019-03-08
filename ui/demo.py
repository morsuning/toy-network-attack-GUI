# -*- coding: utf-8 -*-

from PyQt5 import QtCore, QtGui, QtWidgets


class UiMainWindow(QtWidgets.QMainWindow):
    def __init__(self, main_window):
        super().__init__(flags=None)
        self.setup_ui(main_window)

    def setup_ui(self, main_window):
        main_window.setObjectName("MainWindow")
        main_window.resize(441, 452)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(main_window.sizePolicy().hasHeightForWidth())
        main_window.setSizePolicy(sizePolicy)
        main_window.setCursor(QtGui.QCursor(QtCore.Qt.ArrowCursor))
        self.centralwidget = QtWidgets.QWidget(main_window)
        self.centralwidget.setObjectName("centralwidget")
        self.tabWidget = QtWidgets.QTabWidget(self.centralwidget)
        self.tabWidget.setGeometry(QtCore.QRect(10, 10, 411, 401))
        self.tabWidget.setObjectName("tabWidget")
        self.tab = QtWidgets.QWidget()
        self.tab.setObjectName("tab")
        self.pushButton = QtWidgets.QPushButton(self.tab)
        self.pushButton.setGeometry(QtCore.QRect(20, 10, 111, 32))
        self.pushButton.setObjectName("pushButton")
        self.listView = QtWidgets.QListView(self.tab)
        self.listView.setGeometry(QtCore.QRect(20, 40, 111, 291))
        self.listView.setObjectName("listView")
        self.lineEdit = QtWidgets.QLineEdit(self.tab)
        self.lineEdit.setGeometry(QtCore.QRect(240, 110, 113, 21))
        self.lineEdit.setObjectName("lineEdit")
        self.lineEdit_2 = QtWidgets.QLineEdit(self.tab)
        self.lineEdit_2.setGeometry(QtCore.QRect(240, 140, 113, 21))
        self.lineEdit_2.setObjectName("lineEdit_2")
        self.lineEdit_3 = QtWidgets.QLineEdit(self.tab)
        self.lineEdit_3.setGeometry(QtCore.QRect(240, 170, 113, 21))
        self.lineEdit_3.setObjectName("lineEdit_3")
        self.lineEdit_4 = QtWidgets.QLineEdit(self.tab)
        self.lineEdit_4.setGeometry(QtCore.QRect(240, 200, 113, 21))
        self.lineEdit_4.setObjectName("lineEdit_4")
        self.fontComboBox = QtWidgets.QFontComboBox(self.tab)
        self.fontComboBox.setGeometry(QtCore.QRect(150, 10, 241, 28))
        self.fontComboBox.setEditable(True)
        self.fontComboBox.setObjectName("fontComboBox")
        self.pushButton_2 = QtWidgets.QPushButton(self.tab)
        self.pushButton_2.setGeometry(QtCore.QRect(10, 330, 131, 32))
        self.pushButton_2.setObjectName("pushButton_2")
        self.label = QtWidgets.QLabel(self.tab)
        self.label.setGeometry(QtCore.QRect(150, 49, 60, 21))
        self.label.setObjectName("label")
        self.label_2 = QtWidgets.QLabel(self.tab)
        self.label_2.setGeometry(QtCore.QRect(240, 50, 111, 21))
        self.label_2.setObjectName("label_2")
        self.label_3 = QtWidgets.QLabel(self.tab)
        self.label_3.setGeometry(QtCore.QRect(150, 80, 60, 21))
        self.label_3.setObjectName("label_3")
        self.label_4 = QtWidgets.QLabel(self.tab)
        self.label_4.setGeometry(QtCore.QRect(240, 80, 111, 21))
        self.label_4.setObjectName("label_4")
        self.label_5 = QtWidgets.QLabel(self.tab)
        self.label_5.setGeometry(QtCore.QRect(150, 110, 71, 21))
        self.label_5.setObjectName("label_5")
        self.label_6 = QtWidgets.QLabel(self.tab)
        self.label_6.setGeometry(QtCore.QRect(150, 140, 91, 21))
        self.label_6.setObjectName("label_6")
        self.label_7 = QtWidgets.QLabel(self.tab)
        self.label_7.setGeometry(QtCore.QRect(150, 166, 71, 21))
        self.label_7.setObjectName("label_7")
        self.label_8 = QtWidgets.QLabel(self.tab)
        self.label_8.setGeometry(QtCore.QRect(150, 200, 91, 21))
        self.label_8.setObjectName("label_8")
        self.pushButton_3 = QtWidgets.QPushButton(self.tab)
        self.pushButton_3.setGeometry(QtCore.QRect(270, 330, 121, 32))
        self.pushButton_3.setObjectName("pushButton_3")
        self.lcdNumber = QtWidgets.QLCDNumber(self.tab)
        self.lcdNumber.setGeometry(QtCore.QRect(170, 320, 71, 41))
        self.lcdNumber.setObjectName("lcdNumber")
        self.lineEdit_5 = QtWidgets.QLineEdit(self.tab)
        self.lineEdit_5.setGeometry(QtCore.QRect(240, 230, 113, 21))
        self.lineEdit_5.setReadOnly(True)
        self.lineEdit_5.setClearButtonEnabled(False)
        self.lineEdit_5.setObjectName("lineEdit_5")
        self.lineEdit_6 = QtWidgets.QLineEdit(self.tab)
        self.lineEdit_6.setGeometry(QtCore.QRect(240, 260, 113, 21))
        self.lineEdit_6.setReadOnly(True)
        self.lineEdit_6.setObjectName("lineEdit_6")
        self.label_9 = QtWidgets.QLabel(self.tab)
        self.label_9.setGeometry(QtCore.QRect(150, 230, 60, 21))
        self.label_9.setObjectName("label_9")
        self.label_10 = QtWidgets.QLabel(self.tab)
        self.label_10.setGeometry(QtCore.QRect(150, 260, 81, 21))
        self.label_10.setObjectName("label_10")
        self.checkBox = QtWidgets.QCheckBox(self.tab)
        self.checkBox.setGeometry(QtCore.QRect(210, 290, 141, 21))
        self.checkBox.setChecked(True)
        self.checkBox.setObjectName("checkBox")
        self.tabWidget.addTab(self.tab, "")
        self.tab_3 = QtWidgets.QWidget()
        self.tab_3.setObjectName("tab_3")
        self.tabWidget.addTab(self.tab_3, "")
        self.tab_2 = QtWidgets.QWidget()
        self.tab_2.setObjectName("tab_2")
        self.tabWidget.addTab(self.tab_2, "")
        main_window.setCentralWidget(self.centralwidget)
        self.statusbar = QtWidgets.QStatusBar(main_window)
        self.statusbar.setObjectName("statusbar")
        main_window.setStatusBar(self.statusbar)

        self.retranslateUi(main_window)
        self.tabWidget.setCurrentIndex(2)
        self.fontComboBox.setCurrentIndex(0)
        QtCore.QMetaObject.connectSlotsByName(main_window)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "攻击"))
        self.pushButton.setText(_translate("MainWindow", "发现主机"))
        self.fontComboBox.setCurrentText(_translate("MainWindow", "双向欺骗"))
        self.pushButton_2.setText(_translate("MainWindow", "中断所有主机网络"))
        self.label.setText(_translate("MainWindow", "本机IP："))
        self.label_2.setText(_translate("MainWindow", "Placeholder"))
        self.label_3.setText(_translate("MainWindow", "本机Mac："))
        self.label_4.setText(_translate("MainWindow", "Placeholder"))
        self.label_5.setText(_translate("MainWindow", "攻击目标IP："))
        self.label_6.setText(_translate("MainWindow", "攻击目标Mac："))
        self.label_7.setText(_translate("MainWindow", "伪装对象IP："))
        self.label_8.setText(_translate("MainWindow", "伪装对象Mac："))
        self.pushButton_3.setText(_translate("MainWindow", "开始欺骗"))
        self.label_9.setText(_translate("MainWindow", "中间人IP："))
        self.label_10.setText(_translate("MainWindow", "中间人Mac："))
        self.checkBox.setText(_translate("MainWindow", "本机作为默认中间人"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab), _translate("MainWindow", "ARP欺骗"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_3), _translate("MainWindow", "ICMP欺骗"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_2), _translate("MainWindow", "SYN泛洪攻击"))
