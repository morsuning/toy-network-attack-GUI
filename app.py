import sys
from event import global_event
from PyQt5.QtWidgets import QApplication, QMainWindow

if __name__ == '__main__':
    app = QApplication(sys.argv)
    MainWindow = QMainWindow(flags=None)
    ui = global_event.Event(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())
