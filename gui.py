# -*- coding: utf-8 -*-

import sys
from PyQt5.QtWidgets import (QApplication, QWidget, QTabWidget, QLabel, QDesktopWidget, QGridLayout, 
                QPushButton, QFileDialog, QComboBox, QLineEdit, QCheckBox, QTextEdit,
                QFormLayout, QGroupBox, QVBoxLayout, QLCDNumber, QSlider)
from PyQt5.QtGui import (QIcon, QIntValidator, QRegExpValidator, QFont)
from PyQt5.QtCore import (QRegExp, Qt)
import wmi
from scapy.all import *


class Gui(QWidget):
    
    def __init__(self):
        super(Gui, self).__init__()
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
        grid.addWidget(self.settings_tab(), 2, 3)

        self.resize(500, 580)
        self.setWindowTitle("Packet Generator")
        self.setWindowIcon(QIcon("icons/Walter White Filled-50.png"))
        self.center()   
        self.show()


    def center(self):
        screen = QDesktopWidget().screenGeometry()
        size =  self.geometry()
        self.move((screen.width()-size.width())/2, (screen.height()-size.height())/2)


    def send_packet(self):
        ip = {
        "version": None,
        "header_len": None,
        "total_len_edit": None,
        "identification": None,
        "type_of_service": None,
        "flags": None,
        "offset": None,
        "ttl": None,
        "checksum": None,
        "dst_ip": None,
        "src_ip": None
        }

        if self.ip_packet["version"].text() != "":
            ip["version"] = 4
        else:
            ip["version"] = 4

        if self.ip_packet["header_len"].text() != "":
            ip["header_len"] = long(self.ip_packet["header_len"].text())
        else:
            ip["header_len"] = None

        if self.ip_packet["total_len_edit"].text() != "":
            ip["total_len_edit"] = int(self.ip_packet["total_len_edit"].text())
        else:
            ip["total_len_edit"] = None
        #search how
        if self.ip_packet["type_of_service"] != None:
            ip["type_of_service"] = self.ip_packet["type_of_service"]
        else:
            ip["type_of_service"] = 0x0

        if self.ip_packet["identification"].text() != "":
            ip["identification"] = int(self.ip_packet["identification"].text())
        else:
            ip["identification"] = 1
        #search
        if self.ip_packet["flags"].text() != "":
            ip["flags"] = int(self.ip_packet["flags"].text())
        else:
            ip["flags"] = 0

        if self.ip_packet["offset"].text() != "":
            ip["offset"] = long(self.ip_packet["offset"].text())
        else:
            ip["offset"] = 0L

        if self.ip_packet["ttl"].text() != "":
            ip["ttl"] = int(self.ip_packet["ttl"].text())
        else:
            ip["ttl"] = 64

        if self.ip_packet["checksum"].text() != "":
            ip["checksum"] = self.ip_packet["checksum"].text()
        else:
            ip["checksum"] = None

        if self.ip_packet["dst_ip"].text() != "":
            ip["dst_ip"] = self.ip_packet["dst_ip"].text()
        else:
            ip["dst_ip"] = "127.0.0.1"

        ip["src_ip"] = self.source_ip

        packet_ip = IP(
            version=ip["version"], ihl=ip["header_len"], 
            #tos=ip["type_of_service"],
            len=ip["total_len_edit"],
            id=ip["identification"],
            flags=ip["flags"],
            frag=ip["offset"],
            ttl=ip["ttl"], chksum=ip["checksum"],
            src=ip["src_ip"],
            dst=ip["dst_ip"])
        send(packet_ip)
        print packet_ip.show()









    def settings_tab(self):
        widget = QWidget(self)
        # delay
        lcd = QLCDNumber()
        sld = QSlider(Qt.Horizontal)
        sld.valueChanged.connect(lcd.display)
        #buttons
        load_btn = QPushButton("Load")
        send_btn = QPushButton("Send")
        send_btn.clicked.connect(self.send_packet)
        save_btn = QPushButton("Save")
        #list
        list_edit = QTextEdit()

        form = QFormLayout()
        form.addRow(lcd)
        form.addRow(sld)
        form.addRow(list_edit)
        form.addRow(load_btn)
        form.addRow(save_btn, send_btn)
        widget.setLayout(form)
        return widget


    def ip_tab(self):
        self.ip_packet = {
        "version": None,
        "header_len": None,
        "total_len_edit": None,
        "identification": None,
        "type_of_service": None,
        "flags": None,
        "offset": None,
        "ttl": None,
        "checksum": None,
        "dst_ip": None,
        "dst_mac": None,
        "src_ip": None,
        "src_mac": None
        }
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
        #source, destination ip
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
        # source, dst mac addrecc
        src_mac_lbl = QLabel("Source MAC")
        src_mac_edit = QLineEdit()
        src_mac_edit.setFixedWidth(125)
        dst_mac_lbl = QLabel("Destination MAC")
        dst_mac_edit = QLineEdit()
        dst_mac_edit.setFixedWidth(125)
        mac_reg = QRegExp(
            "[0-9a-z]{2,2}\\:[0-9a-z]{2,2}\\:[0-9a-z]{2,2}\\:[0-9a-z]{2,2}\\:[0-9a-z]{2,2}\\:[0-9a-z]{2,2}"
            )
        src_mac_validator = QRegExpValidator(mac_reg, src_mac_edit)
        dst_mac_validator = QRegExpValidator(mac_reg, dst_mac_edit)
        src_mac_edit.setValidator(src_mac_validator)
        dst_mac_edit.setValidator(dst_mac_validator)

        self.ip_packet["version"] = version_edit
        self.ip_packet["header_len"] = header_len_edit
        self.ip_packet["total_len_edit"] = total_len_edit
        self.ip_packet["identification"] = identification_edit
        self.ip_packet["type_of_service"] = type_of_service_edit
        self.ip_packet["flags"] = flags_edit
        self.ip_packet["offset"] = flag_offset_edit
        self.ip_packet["ttl"] = ttl_edit
        self.ip_packet["checksum"] = header_checksum_edit
        self.ip_packet["dst_ip"] = dst_edit
        self.ip_packet["dst_mac"] = dst_mac_edit
        self.ip_packet["src_ip"] = src_edit
        self.ip_packet["src_mac"] = src_mac_edit

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
        form.addRow(src_mac_lbl)
        form.addRow(src_mac_edit)
        form.addRow(dst_mac_lbl)
        form.addRow(dst_mac_edit)

        widget.setLayout(form)
        return widget


    def icmp_tab(self):
        self.icmp_packet = {
        "type": None,
        "code": None,
        "checksum": None,
        "data": None
        }
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

        self.icmp_packet["type"] = type_edit
        self.icmp_packet["code"] = code_edit
        self.icmp_packet["checksum"] = checksum_edit
        self.icmp_packet["data"] = data


        form = QFormLayout()
        form.addRow(type_lbl, type_edit)
        form.addRow(code_lbl, code_edit)
        form.addRow(checksum_checkbox, checksum_edit)
        form.addRow(data)
        widget.setLayout(form)
        return widget


    def tcp_tab(self):
        self.tcp_packet = {
        "src_port": None,
        "dst_port": None,
        "seq": None,
        "ack": None,
        "header_len": None,
        "reserved_bits": None,
        "cvr": None,
        "ecn": None,
        "urg": None,
        "ack": None,
        "syn": None,
        "fin": None,
        "psh": None,
        "win_size": None,
        "checksum": None,
        "urgent": None,
        "options": None
        }
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

        self.tcp_packet["src_port"] = src_port_edit
        self.tcp_packet["dst_port"] = dst_port_edit
        self.tcp_packet["seq"] = seq_edit
        self.tcp_packet["ack"] = ack_edit
        self.tcp_packet["header_len"] = header_len_edit
        self.tcp_packet["reserved_bits"] = reserved_bits_edit
        self.tcp_packet["cvr"] = cvr_checkbox
        self.tcp_packet["ecn"] = ecn_echo_checkbox
        self.tcp_packet["urg"] = urg
        self.tcp_packet["ack"] = ack
        self.tcp_packet["syn"] = syn
        self.tcp_packet["fin"] = fin
        self.tcp_packet["psh"] = psh
        self.tcp_packet["win_size"] = win_size_edit
        self.tcp_packet["checksum"] = checksum_edit
        self.tcp_packet["urgent"] = urgent_ptr_edit
        self.tcp_packet["options"] = options_edit

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
        self.source_ip = ip[index][0]
        self.source_mac = mac[index]


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


if __name__ == "__main__":
    app = QApplication(sys.argv)
    ex = Gui()
    sys.exit(app.exec_())