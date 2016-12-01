# -*- coding: utf-8 -*-

import sys
from PyQt5.QtWidgets import (QApplication, QWidget, QTabWidget, QLabel, QDesktopWidget, QGridLayout, 
                QPushButton, QFileDialog, QComboBox, QLineEdit, QCheckBox, QTextEdit,
                QFormLayout, QGroupBox, QVBoxLayout)
from PyQt5.QtGui import (QIcon, QIntValidator, QRegExpValidator, QFont)
from PyQt5.QtCore import (QRegExp, Qt)
from PyQt5.QtNetwork import (QNetworkInterface)
import wmi


class Gui(QWidget):
    
    def __init__(self):
        super().__init__()
        self.initUI()
        
    def initUI(self):
        tab = QTabWidget()
        tab.addTab(self.icmp_tab(), "ICMP")
        tab.addTab(self.tcp_tab(), "TCP")
        tab.addTab(self.udp_tab(), "UDP")
        #ComboBox
        interfaces = QComboBox(self)
        list_interfaces = self.get_interfaces()[0]
        list_interfaces.insert(0, "")
        interfaces.addItems(list_interfaces)
        interfaces.activated[str].connect(self.onActivated)

        grid = QGridLayout(self)
        grid.addWidget(interfaces, 1, 0, 1, 3)
        grid.addWidget(self.ip_tab(), 2, 0)
        grid.addWidget(tab, 2, 1)
        grid.addWidget(self.settings(), 2, 3)
        
        self.resize(500, 580)
        self.setWindowTitle("Packet Generator")
        self.setWindowIcon(QIcon("icons/Walter White Filled-50.png"))
        self.center()   
        self.show()


    def center(self):
        screen = QDesktopWidget().screenGeometry()
        size =  self.geometry()
        self.move((screen.width()-size.width())/2, (screen.height()-size.height())/2)


    def settings(self):
        widget = QWidget(self)
        grid = QGridLayout()
        lbl = QLabel("test")
        grid.addWidget(lbl, 0, 0)
        widget.setLayout(grid)
        return widget


    def ip_tab(self):
        widget = QWidget(self)
        #main label
        ip_lbl = QLabel("IP")
        font = QFont("Verdana", 16, QFont.Bold)
        ip_lbl.setFont(font)
        ip_lbl.setAlignment(Qt.AlignCenter)
        # verison
        version_lbl = QLabel("Version")
        version_edit = QLineEdit()
        version_edit.setValidator(QIntValidator())
        version_edit.setMaxLength(1)
        version_edit.setFixedWidth(20)
        # header length
        header_len_lbl = QLabel("Header length")
        header_len_edit = QLineEdit()
        header_len_edit.setValidator(QIntValidator())
        header_len_edit.setMaxLength(2)
        header_len_edit.setFixedWidth(30)
        # total length
        total_len_lbl = QLabel("Total length")
        total_len_edit = QLineEdit()
        total_len_edit.setValidator(QIntValidator())
        total_len_edit.setMaxLength(5)
        total_len_edit.setFixedWidth(45)
        # identification
        identification_lbl = QLabel("Identification")
        identification_edit = QLineEdit()
        identification_edit.setFixedWidth(45)
        identification_edit.setValidator(QIntValidator())
        # type of service
        type_of_service_lbl = QLabel("Type of service")
        type_of_service_edit = QLineEdit()
        type_of_service_edit.setFixedWidth(45)
        # flags
        flags_lbl = QLabel("Flags")
        flags_edit = QLineEdit()
        flags_edit.setValidator(QIntValidator(0, 2))
        flags_edit.setMaxLength(1)
        flags_edit.setFixedWidth(45)
        # flag offset
        flag_offset_lbl = QLabel("Flag offset")
        flag_offset_edit = QLineEdit()
        flag_offset_edit.setFixedWidth(45)
        # TTL
        ttl_lbl = QLabel("TTL")
        ttl_edit = QLineEdit()
        ttl_edit.setValidator(QIntValidator(0, 255))
        ttl_edit.setMaxLength(3)
        ttl_edit.setFixedWidth(45)
        #header checksum
        header_checksum_checkbox = QCheckBox("Header checksum")
        header_checksum_edit = QLineEdit()
        header_checksum_edit.setDisabled(1)
        header_checksum_edit.setFixedWidth(45)
        #source, destination
        src_lbl = QLabel("Source IP")
        src_edit = QLineEdit()
        src_edit.setFixedWidth(100)
        dst_lbl = QLabel("Destination IP")
        dst_edit = QLineEdit()
        dst_edit.setFixedWidth(100)
        ip_reg = QRegExp("[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}")
        src_validator = QRegExpValidator(ip_reg, src_edit)
        dst_validator = QRegExpValidator(ip_reg, dst_edit)
        src_edit.setValidator(src_validator)
        dst_edit.setValidator(dst_validator)

        form = QFormLayout()
        form.addRow(ip_lbl)
        form.addRow(version_lbl, version_edit)
        form.addRow(header_len_lbl, header_len_edit)
        form.addRow(total_len_lbl, total_len_edit)
        form.addRow(type_of_service_lbl, type_of_service_edit)
        form.addRow(identification_lbl, identification_edit)
        form.addRow(flags_lbl, flags_edit)
        form.addRow(flag_offset_lbl, flag_offset_edit)
        form.addRow(ttl_lbl, ttl_edit)
        form.addRow(header_checksum_checkbox, header_checksum_edit)
        form.addRow(src_lbl)
        form.addRow(src_edit)
        form.addRow(dst_lbl)
        form.addRow(dst_edit)

        widget.setLayout(form)
        return widget


    def icmp_tab(self):
        widget = QWidget(self)
        #ICMP type
        type_lbl = QLabel("Type")
        type_edit = QLineEdit()
        type_edit.setValidator(QIntValidator(0, 255))
        type_edit.setFixedWidth(45)
        # code
        code_lbl = QLabel("Code")
        code_edit = QLineEdit()
        code_edit.setValidator(QIntValidator(0, 15))
        code_edit.setFixedWidth(45)
        # checksum
        checksum_checkbox = QCheckBox("Checksum")
        checksum_edit = QLineEdit()
        checksum_edit.setDisabled(1)
        checksum_edit.setFixedWidth(45)
        # data
        data = QTextEdit()

        form = QFormLayout()
        form.addRow(type_lbl, type_edit)
        form.addRow(code_lbl, code_edit)
        form.addRow(checksum_checkbox, checksum_edit)
        form.addRow(data)
        widget.setLayout(form)
        return widget


    def tcp_tab(self):
        widget = QWidget(self)
        # src port
        src_port_lbl = QLabel("Souce port")
        src_port_edit = QLineEdit()
        src_port_edit.setValidator(QIntValidator(0, 65535))
        src_port_edit.setFixedWidth(45)
        # dst port
        dst_port_lbl = QLabel("Destination port")
        dst_port_edit = QLineEdit()
        dst_port_edit.setValidator(QIntValidator(0, 65535))
        dst_port_edit.setFixedWidth(45)
        #seq number
        seq_lbl = QLabel("Seq number")
        seq_edit = QLineEdit()
        seq_edit.setValidator(QIntValidator())
        # ack number
        ack_lbl = QLabel("Ack number")
        ack_edit = QLineEdit()
        ack_edit.setValidator(QIntValidator())
        # header len
        header_len_lbl = QLabel("Header length")
        header_len_edit = QLineEdit()
        header_len_edit.setValidator(QIntValidator())
        header_len_edit.setMaxLength(2)
        header_len_edit.setFixedWidth(30)
        # 4 reserved bits
        reserved_bits_lbl = QLabel("Reserved bits(4)")
        reserved_bits_edit = QLineEdit()
        reserved_bits_edit.setFixedWidth(20)
        # cwr and ecn-echo
        cvr_checkbox = QCheckBox("CWR")
        ecn_echo_checkbox = QCheckBox("ECN-echo")
        # control bits
        urg = QCheckBox("URG")
        ack = QCheckBox("ACK")
        psh = QCheckBox("PSH")
        rst = QCheckBox("RST")
        syn = QCheckBox("SYN")
        fin = QCheckBox("FIN")

        # win size
        win_size_lbl = QLabel("Windows size")
        win_size_edit = QLineEdit()
        win_size_edit.setValidator(QIntValidator())
        win_size_edit.setFixedWidth(45)
        # checksum
        checksum_checkbox = QCheckBox("Checksum")
        checksum_edit = QLineEdit()
        checksum_edit.setDisabled(1)
        checksum_edit.setValidator(QIntValidator())
        checksum_edit.setFixedWidth(45)
        # urgent pointer
        urgent_ptr_lbl = QLabel("Urgent pointer")
        urgent_ptr_edit = QLineEdit()
        urgent_ptr_edit.setValidator(QIntValidator())
        urgent_ptr_edit.setFixedWidth(45)
        urgent_ptr_edit.setDisabled(1)
        # options
        options_edit = QTextEdit()

        form = QFormLayout()
        form.addRow(src_port_lbl, src_port_edit)
        form.addRow(dst_port_lbl, dst_port_edit)
        form.addRow(seq_lbl, seq_edit)
        form.addRow(ack_lbl, ack_edit)
        form.addRow(header_len_lbl, header_len_edit)
        form.addRow(reserved_bits_lbl, reserved_bits_edit)
        form.addRow(cvr_checkbox, ecn_echo_checkbox)
        form.addRow(urg, ack)
        form.addRow(psh, rst)
        form.addRow(syn, fin)
        form.addRow(win_size_lbl, win_size_edit)
        form.addRow(checksum_checkbox, checksum_edit)
        form.addRow(urgent_ptr_lbl, urgent_ptr_edit)
        form.addRow(options_edit)
        widget.setLayout(form)
        return widget


    def udp_tab(self):
        widget = QWidget(self)
        # src port
        src_port_lbl = QLabel("Source port")
        src_port_edit = QLineEdit()
        src_port_edit.setValidator(QIntValidator(0, 65535))
        src_port_edit.setFixedWidth(45)
        # dst port
        dst_port_lbl = QLabel("Destination port")
        dst_port_edit = QLineEdit()
        dst_port_edit.setValidator(QIntValidator(0, 65535))
        dst_port_edit.setFixedWidth(45)
        # length
        len_lbl = QLabel("Length")
        len_edit = QLineEdit()
        len_edit.setValidator(QIntValidator())
        len_edit.setFixedWidth(45)
        # checksum
        checksum_checkbox = QCheckBox("Checksum")
        checksum_edit = QLineEdit()
        checksum_edit.setDisabled(1)
        checksum_edit.setValidator(QIntValidator())
        checksum_edit.setFixedWidth(45)
        # data
        data = QTextEdit()

        form = QFormLayout()
        form.addRow(src_port_lbl, src_port_edit)
        form.addRow(dst_port_lbl, dst_port_edit)
        form.addRow(len_lbl, len_edit)
        form.addRow(checksum_checkbox, checksum_edit)
        form.addRow(data)
        widget.setLayout(form)
        return widget


    #for ComboBox
    def onActivated(self, text):
        names = self.get_interfaces()[0]
        ip = self.get_interfaces()[1]
        mac = self.get_interfaces()[2]
        index = names.index(text)
        source_ip = ip[index][0]
        source_mac = mac[index]
        print(source_ip)
        print(source_mac)



    def get_interfaces(self):
        c = wmi.WMI()
        intefsc = []
        ip = []
        mac = []
        for interface in c.Win32_NetworkAdapterConfiguration (IPEnabled=1):
            intefsc.append(interface.Description)
            ip.append(interface.IPAddress)
            mac.append(interface.MACAddress)
        return intefsc, ip, mac
            

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