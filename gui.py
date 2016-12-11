# -*- coding: utf-8 -*-

import sys
from PyQt5.QtWidgets import (QApplication, QWidget, QTabWidget, QLabel, QDesktopWidget, QGridLayout, 
                QPushButton, QFileDialog, QComboBox, QLineEdit, QCheckBox, QTextEdit,
                QFormLayout, QGroupBox, QVBoxLayout, QLCDNumber, QSlider)
from PyQt5.QtGui import (QIcon, QIntValidator, QRegExpValidator, QFont, QPixmap)
from PyQt5.QtCore import (QRegExp, Qt)
import wmi
from scapy.all import *


class Gui(QWidget):
    
    def __init__(self):
        super(Gui, self).__init__()
        self.initUI()
        
    def initUI(self):
        tab = QTabWidget()
        tab.addTab(self.ip_right_tab(), "IP")
        tab.addTab(self.icmp_tab(), "ICMP")
        tab.addTab(self.tcp_tab(), "TCP")
        tab.addTab(self.udp_tab(), "UDP")
        tab.currentChanged[int].connect(self.callback_current_tab(tab))
        # 0 - ip, 1 - icmp, 2 - tcp, 3 - udp
        self.current_tab = 0
        #ComboBox
        interfaces = QComboBox(self)
        list_interfaces = self.get_interfaces()[0]
        list_interfaces.insert(0, "")
        interfaces.addItems(list_interfaces)
        interfaces.activated[str].connect(self.onActivated)
        grid = QGridLayout(self)
        grid.addWidget(interfaces, 1, 0, 1, 3)
        grid.addWidget(self.ip_left_tab(), 2, 0)
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


    # current tab
    def callback_current_tab(self, tab):
        return lambda: self.get_current_tab(tab)


    def get_current_tab(self, tab):
        self.current_tab = tab.currentIndex()


    # enable/disable checksum field 
    def callbackChecksum(self, checkbox, edit): 
        return lambda: self.changeChecksumField(checkbox, edit)


    def changeChecksumField(self, checkbox, edit):
        if checkbox.isChecked(): 
            edit.setDisabled(0) 
        else: 
            edit.setDisabled(1)

    def packing_ip(self):
        ip = {
            "version": None,
            "ihl": None,
            "len": None,
            "identification": None,
            "type_of_service": None,
            "flags": None,
            "offset": None,
            "ttl": None,
            "checksum": None,
            "dst_ip": None,
            "src_ip": None,
            "daa": None
            }

        if self.ip_packet["version"].text() != "":
            ip["version"] = 4
        else:
            ip["version"] = 4

        if self.ip_packet["ihl"].text() != "":
            ip["ihl"] = long(self.ip_packet["ihl"].text())
        else:
            ip["ihl"] = None

        if self.ip_packet["len"].text() != "":
            ip["len"] = int(self.ip_packet["len"].text())
        else:
            ip["len"] = None
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
            ip["checksum"] = int(self.ip_packet["checksum"].text())
        else:
            ip["checksum"] = None

        if self.ip_packet["dst_ip"].text() != "":
            ip["dst_ip"] = self.ip_packet["dst_ip"].text()
        else:
            ip["dst_ip"] = "127.0.0.1"

        if self.ip_packet["src_ip"].text() != "":
            ip["src_ip"] = self.ip_packet["src_ip"].text()
        else:
            ip["src_ip"] = self.source_ip

        flag = 0
        if self.ip_packet["data"].toPlainText() != "":
            ip["data"]  = str(self.ip_packet["data"].toPlainText())
            flag = 1       

        if flag:
            ip_full = IP(
                version=ip["version"],
                ihl=ip["ihl"], 
                #tos=ip["type_of_service"],
                len=ip["len"],
                id=ip["identification"],
                flags=ip["flags"],
                frag=ip["offset"],
                ttl=ip["ttl"],
                chksum=ip["checksum"],
                src=ip["src_ip"],
                dst=ip["dst_ip"],
                )/ip["data"]
        else:
            ip_full = IP(
                version=ip["version"], ihl=ip["ihl"], 
                #tos=ip["type_of_service"],
                len=ip["len"],
                id=ip["identification"],
                flags=ip["flags"],
                frag=ip["offset"],
                ttl=ip["ttl"],
                chksum=ip["checksum"],
                src=ip["src_ip"],
                dst=ip["dst_ip"]
                )

        return ip_full


    def packing_icmp(self):
        icmp = {
            "type": None,
            "code": None,
            "checksum": None,
            "id": None,
            "seq": None,
            "data": None
            }

        if self.icmp_packet["type"][0].checkState() != 0:
            icmp["type"] = self.icmp_packet["type"][0].text()
        elif self.icmp_packet["type"][1].checkState() != 0:
            icmp["type"] = self.icmp_packet["type"][1].text()

        if self.icmp_packet["code"].text() != "":
            icmp["code"] = int(self.icmp_packet["code"].text())
        else:
            icmp["code"] = 0

        if self.icmp_packet["checksum"].text() != "":
            icmp["checksum"] = int(self.icmp_packet["checksum"].text())
        else:
            icmp["checksum"] = None

        if self.icmp_packet["id"].text() != "":
            icmp["id"] = int(self.icmp_packet["id"].text())
        else:
            icmp["id"] = 0

        if self.icmp_packet["seq"].text() != "":
            icmp["seq"] = int(self.icmp_packet["seq"].text())
        else:
            icmp["seq"] = 0

        flag = 0
        if self.icmp_packet["data"].toPlainText() != "":
            icmp["data"] = str(self.icmp_packet["data"].toPlainText())
            flag = 1

        if flag:
            icmp_full = ICMP(
                type=str(icmp["type"]),
                code=icmp["code"],
                chksum=icmp["checksum"],
                id=icmp["id"],
                seq=icmp["seq"]
            )/icmp["data"]
        else:
            icmp_full = ICMP(
                type=str(icmp["type"]),
                code=icmp["code"],
                chksum=icmp["checksum"],
                id=icmp["id"],
                seq=icmp["seq"]
            )

        return icmp_full


    def packing_udp(self):
        udp = {
            "sport": None,
            "dport": None,
            "len": None,
            "checksum": None,
            "data": None
            }
        if self.udp_packet["sport"].text() != "":
            udp["sport"] = int(self.udp_packet["sport"].text())
        if self.udp_packet["dport"].text() != "":
            udp["dport"] = int(self.udp_packet["dport"].text())
        if self.udp_packet["len"].text() != "":
            udp["len"] = int(self.udp_packet["len"].text())
        else:
            pass
        if self.udp_packet["checksum"].text() != "":
            udp["checksum"] = int(self.udp_packet["checksum"].text())
        flag = 0
        if self.udp_packet["data"].toPlainText() != "":
            udp["data"] = str(self.udp_packet["data"].toPlainText())
            flag = 1

        if flag:
            udp_full = UDP(
                sport=udp["sport"],
                dport=udp["dport"],
                len=udp["len"],
                chksum=udp["checksum"]
                )/udp["data"]
        else:
            udp_full = UDP(
                sport=udp["sport"],
                dport=udp["dport"],
                len=udp["len"],
                chksum=udp["checksum"]
                )

        return udp_full


    def packing_tcp(self):
        tcp = {
            "sport": None,
            "dport": None,
            "seq": None,
            "ack_num": None,
            # "header_len": None,
            "reserved_bits": None,
            "flags": None,
            "win_size": None,
            "checksum": None,
            "urgent": None,
            "data": None
            }


        if self.tcp_packet["sport"].text() != "":
            tcp["sport"] = int(self.tcp_packet["sport"].text())
        else:
            tcp["sport"] = None
        if self.tcp_packet["dport"].text() != "":
            tcp["dport"] = int(self.tcp_packet["dport"].text())
        else:
            tcp["dport"] = None
        if self.tcp_packet["seq"].text() != "":
            tcp["seq"] = int(self.tcp_packet["seq"].text())
        else:
            tcp["seq"] = None
        if self.tcp_packet["ack_num"].text() != "":
            tcp["ack_num"] = int(self.tcp_packet["ack_num"].text())
        else:
            tcp["ack_num"] = None
        if self.tcp_packet["reserved_bits"].text() != "":
            tcp["reserved_bits"] = int(self.tcp_packet["reserved_bits"].text())
        else:
            tcp["reserved_bits"] = None
        if self.tcp_packet["cvr"].checkState() == 2:
            tcp["flags"] = "C"
        if self.tcp_packet["ecn"].checkState() == 2:
            tcp["flags"] = "E"
        if self.tcp_packet["urg"].checkState() == 2:
            tcp["flags"] = "U"
        if self.tcp_packet["syn"].checkState() == 2:
            tcp["flags"] = "S"
        if self.tcp_packet["ack"].checkState() == 2:
            tcp["flags"] = "A"
        if self.tcp_packet["fin"].checkState() == 2:
            tcp["flags"] = "F"
        if self.tcp_packet["psh"].checkState() == 2:
            tcp["flags"] = "P"
        if self.tcp_packet["rst"].checkState() == 2:
            tcp["flags"] = "R"
        #if not flag => make SYN flag
        if tcp["flags"] == None:
            tcp["flags"] = "S"

        if self.tcp_packet["win_size"].text() != "":
            tcp["win_size"] = int(self.tcp_packet["win_size"].text())
        else:
            tcp["win_size"] = None

        if self.tcp_packet["checksum"].text() != "":
            tcp["checksum"] = int(self.tcp_packet["checksum"].text())

        flag = 0
        if self.tcp_packet["data"].toPlainText() != "":
            tcp["data"] = str(self.tcp_packet["data"].toPlainText())
            flag = 1


        if flag:
            tcp_full = TCP(
                sport=tcp["sport"],
                dport=tcp["dport"],
                seq=tcp["seq"],
                ack=tcp["ack_num"],
                flags=tcp["flags"],
                window=tcp["win_size"],
                chksum=tcp["checksum"]
                )/tcp["data"]
        else:
            tcp_full = TCP(
                sport=tcp["sport"],
                dport=tcp["dport"],
                seq=tcp["seq"],
                ack=tcp["ack_num"],
                flags=tcp["flags"],
                window=tcp["win_size"],
                chksum=tcp["checksum"]
                )

        return tcp_full


    def send_packet(self):
        ip_full = self.packing_ip()
        protocol = None
        if self.current_tab == 0:
            main_packet = ip_full
            send(main_packet)
            print main_packet.show()
            return
        elif self.current_tab == 1:
            protocol = self.packing_icmp()
        elif self.current_tab == 2:
            protocol = self.packing_tcp()
        elif self.current_tab == 3:
            protocol = self.packing_udp()
        main_packet = ip_full/protocol
        send(main_packet)
        print main_packet.show()


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


    def ip_left_tab(self):
        self.ip_packet = {
        "version": None,
        "ihl": None,
        "len": None,
        "identification": None,
        "type_of_service": None,
        "flags": None,
        "offset": None,
        "ttl": None,
        "checksum": None,
        "dst_ip": None,
        # "dst_mac": None,
        "src_ip": None,
        # "src_mac": None,
        "data": None
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
        ihl_lbl = QLabel("IHL")
        ihl_edit = QLineEdit()
        ihl_edit.setValidator(QIntValidator())
        ihl_edit.setMaxLength(2)
        ihl_edit.setFixedWidth(30)
        # total length
        len_lbl = QLabel("Total length")
        len_edit = QLineEdit()
        len_edit.setValidator(QIntValidator())
        len_edit.setMaxLength(5)
        len_edit.setFixedWidth(45)
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
        header_checksum_checkbox.stateChanged.connect(
            self.callbackChecksum(header_checksum_checkbox, header_checksum_edit)
            )
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
        # src_mac_lbl = QLabel("Source MAC")
        # src_mac_edit = QLineEdit()
        # src_mac_edit.setFixedWidth(125)
        # dst_mac_lbl = QLabel("Destination MAC")
        # dst_mac_edit = QLineEdit()
        # dst_mac_edit.setFixedWidth(125)
        # mac_reg = QRegExp(
        #     "[0-9a-z]{2,2}\\:[0-9a-z]{2,2}\\:[0-9a-z]{2,2}\\:[0-9a-z]{2,2}\\:[0-9a-z]{2,2}\\:[0-9a-z]{2,2}"
        #     )
        # src_mac_validator = QRegExpValidator(mac_reg, src_mac_edit)
        # dst_mac_validator = QRegExpValidator(mac_reg, dst_mac_edit)
        # src_mac_edit.setValidator(src_mac_validator)
        # dst_mac_edit.setValidator(dst_mac_validator)

        data = QTextEdit()

        self.ip_packet["version"] = version_edit
        self.ip_packet["ihl"] = ihl_edit
        self.ip_packet["len"] = len_edit
        self.ip_packet["identification"] = identification_edit
        self.ip_packet["type_of_service"] = type_of_service_edit
        self.ip_packet["flags"] = flags_edit
        self.ip_packet["offset"] = flag_offset_edit
        self.ip_packet["ttl"] = ttl_edit
        self.ip_packet["checksum"] = header_checksum_edit
        self.ip_packet["dst_ip"] = dst_edit
        # self.ip_packet["dst_mac"] = dst_mac_edit
        self.ip_packet["src_ip"] = src_edit
        # self.ip_packet["src_mac"] = src_mac_edit
        self.ip_packet["data"] = data

        form = QFormLayout()
        form.addRow(ip_lbl)
        form.addRow(version_lbl, version_edit)
        form.addRow(ihl_lbl, ihl_edit)
        form.addRow(len_lbl, len_edit)
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
        # form.addRow(src_mac_lbl)
        # form.addRow(src_mac_edit)
        # form.addRow(dst_mac_lbl)
        # form.addRow(dst_mac_edit)
        form.addRow(data)

        widget.setLayout(form)
        return widget

    def ip_right_tab(self):
        widget = QWidget(self)
        lbl = QLabel()
        pixmap = QPixmap("icons/Binary File Filled-50.png")
        lbl.setPixmap(pixmap)
        form = QFormLayout()
        form.addRow(lbl)
        widget.setLayout(form)
        return widget


    def icmp_tab(self):
        self.icmp_packet = {
        "type": None,
        "code": None,
        "checksum": None,
        "id": None,
        "seq": None,
        "address_mask": None
        }
        widget = QWidget(self)
        # ICMP type
        echo_reply_lbl = QCheckBox("echo-reply")
        echo_request_lbl = QCheckBox("echo-request")
        # code
        code_lbl = QLabel("Code")
        code_edit = QLineEdit()
        code_edit.setValidator(QIntValidator())
        code_edit.setFixedWidth(45)
        # checksum
        checksum_checkbox = QCheckBox("Checksum")
        checksum_edit = QLineEdit()
        checksum_edit.setDisabled(1)
        checksum_edit.setFixedWidth(45)
        checksum_checkbox.stateChanged.connect(
            self.callbackChecksum(checksum_checkbox, checksum_edit)
            )
        # id
        id_lbl = QLabel("Identificator")
        id_edit = QLineEdit()
        id_edit = QLineEdit()
        id_edit.setValidator(QIntValidator())
        id_edit.setFixedWidth(45)
        # seq
        seq_lbl = QLabel("Seq")
        seq_edit = QLineEdit()
        seq_edit = QLineEdit()
        seq_edit.setValidator(QIntValidator())
        seq_edit.setFixedWidth(45)

        data = QTextEdit()

        self.icmp_packet["type"] = (echo_reply_lbl, echo_request_lbl)
        self.icmp_packet["code"] = code_edit
        self.icmp_packet["checksum"] = checksum_edit
        self.icmp_packet["id"] = id_edit
        self.icmp_packet["seq"] = seq_edit
        self.icmp_packet["data"] = data


        form = QFormLayout()
        form.addRow(echo_reply_lbl, echo_request_lbl)
        form.addRow(code_lbl, code_edit)
        form.addRow(checksum_checkbox, checksum_edit)
        form.addRow(id_lbl, id_edit)
        form.addRow(seq_lbl, seq_edit)
        form.addRow(data)
        widget.setLayout(form)
        return widget


    def tcp_tab(self):

        self.tcp_packet = {
        "sport": None,
        "dport": None,
        "seq": None,
        "ack_num": None,
        "header_len": None,
        "reserved_bits": None,
        "cvr": None,
        "ecn": None,
        "urg": None,
        "ack": None,
        "syn": None,
        "fin": None,
        "psh": None,
        "rst": None,
        "win_size": None,
        "checksum": None,
        "urgent": None,
        "data": None
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
        checksum_checkbox.stateChanged.connect(
            self.callbackChecksum(checksum_checkbox, checksum_edit)
            )
        # urgent pointer
        urgent_ptr_lbl = QLabel("Urgent pointer")
        urgent_ptr_edit = QLineEdit()
        urgent_ptr_edit.setValidator(QIntValidator())
        urgent_ptr_edit.setFixedWidth(45)
        urgent_ptr_edit.setDisabled(1)
        # options
        data = QTextEdit()

        self.tcp_packet["sport"] = src_port_edit
        self.tcp_packet["dport"] = dst_port_edit
        self.tcp_packet["seq"] = seq_edit
        self.tcp_packet["ack_num"] = ack_edit
        self.tcp_packet["header_len"] = header_len_edit
        self.tcp_packet["reserved_bits"] = reserved_bits_edit
        self.tcp_packet["cvr"] = cvr_checkbox
        self.tcp_packet["ecn"] = ecn_echo_checkbox
        self.tcp_packet["urg"] = urg
        self.tcp_packet["ack"] = ack
        self.tcp_packet["syn"] = syn
        self.tcp_packet["fin"] = fin
        self.tcp_packet["psh"] = psh
        self.tcp_packet["rst"] = rst
        self.tcp_packet["win_size"] = win_size_edit
        self.tcp_packet["checksum"] = checksum_edit
        self.tcp_packet["urgent"] = urgent_ptr_edit
        self.tcp_packet["data"] = data

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
        form.addRow(data)
        widget.setLayout(form)
        return widget


    def udp_tab(self):
        self.udp_packet = {
        "sport": None,
        "dport": None,
        "len": None,
        "checksum": None,
        "data": None
        }

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
        checksum_checkbox.stateChanged.connect(
            self.callbackChecksum(checksum_checkbox, checksum_edit)
            )
        # data
        data = QTextEdit()

        self.udp_packet["sport"]  = src_port_edit
        self.udp_packet["dport"]  = dst_port_edit
        self.udp_packet["len"]  = len_edit
        self.udp_packet["checksum"]  = checksum_edit
        self.udp_packet["data"]  = data

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