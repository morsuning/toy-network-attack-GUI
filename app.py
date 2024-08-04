import sys

from PyQt5.QtWidgets import QApplication, QMainWindow

from event import main_window

if __name__ == '__main__':
    app = QApplication(sys.argv)
    MainWindow = QMainWindow()
    ui = main_window.Event(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())
