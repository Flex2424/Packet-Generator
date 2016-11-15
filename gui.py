# -*- coding: utf-8 -*-

import sys
from PyQt5.QtWidgets import QApplication, QWidget, QTabWidget, QLabel

class Example(QWidget):
    
    def __init__(self):
        super().__init__()
        self.initUI()
        
    def initUI(self):
        tab = QTabWidget(self)
        tab.addTab(QLabel("test1"), "ICMP")
        tab.addTab(QLabel("test2"), "IP")
        tab.addTab(QLabel("test3"), "TCP")
        tab.addTab(QLabel("test4"), "UDP")



        self.setGeometry(300, 300, 300, 200)
        self.setWindowTitle("Packet Generator")    
        self.show()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    ex = Example()
    sys.exit(app.exec_())