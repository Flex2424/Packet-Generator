# -*- coding: utf-8 -*-

import sys
from PyQt5.QtWidgets import (QApplication, QWidget, QTabWidget, QLabel, QDesktopWidget, QGridLayout, 
                QPushButton, QFileDialog, QComboBox)
from PyQt5.QtGui import QIcon


class Gui(QWidget):
    
    def __init__(self):
        super().__init__()
        self.initUI()
        
    def initUI(self):
        tab = QTabWidget()
        tab.addTab(self.icmp_tab(), "ICMP")
        tab.addTab(self.ip_tab(), "IP")
        tab.addTab(self.tcp_tab(), "TCP")
        tab.addTab(self.udp_tab(), "UDP")
        interfaces = QComboBox(self)
        interfaces.addItems(["eth0", "wmnet1", "wmnet2"])

        grid = QGridLayout(self)
        grid.addWidget(interfaces, 1, 0)
        grid.addWidget(tab, 2, 0)
        

        self.resize(500, 580)
        self.setWindowTitle("Packet Generator")
        self.setWindowIcon(QIcon("icons/Walter White Filled-50.png"))
        self.center()   
        self.show()


    def center(self):
        screen = QDesktopWidget().screenGeometry()
        size =  self.geometry()
        self.move((screen.width()-size.width())/2, (screen.height()-size.height())/2)


    def ip_tab(self):
        widget = QWidget(self)
        btn = QPushButton("Button")
        grid = QGridLayout()
        #grid.setSpacing(10)
        grid.addWidget(btn, 1, 0)
        #widget.setLayout(grid)
        return widget


    def icmp_tab(self):
        widget = QWidget(self)
        btn = QPushButton("Button2")
        grid = QGridLayout()
        #grid.setSpacing(10)
        grid.addWidget(btn, 1, 0)
        #widget.setLayout(grid)
        return widget


    def tcp_tab(self):
        widget = QWidget(self)
        btn = QPushButton("Button3")
        grid = QGridLayout()
        #grid.setSpacing(10)
        grid.addWidget(btn, 3, 0)
        #widget.setLayout(grid)
        return widget


    def udp_tab(self):
        widget = QWidget(self)
        btn = QPushButton("Button4")
        grid = QGridLayout()
        #grid.setSpacing(10)
        grid.addWidget(btn, 4, 0)
        #widget.setLayout(grid)
        return widget


    # def showDialog(self):
    #     filename = QFileDialog.getFileOpen(self, "Open File", "c://")

    #     f = open(fname, 'r')
        
    #     with f:        
    #         data = f.read()
    #         self.textEdit.setText(data) 


    # def closeEvent(self, event):
    #     reply = QMessageBox.question(self, "Why??",
    #         "Are you sure to quit?", QMessageBox.Yes, QMessageBox.No)

    #     if reply == QMessageBox.Yes:
    #         event.accept()
    #     else:
    #         event.ignore()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    ex = Gui()
    sys.exit(app.exec_())