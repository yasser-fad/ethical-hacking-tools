#!/usr/bin/env python3
import argparse
import scapy.all as scapy


# take IP argument to scan all connected devices
def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP / IP range.")
    options = parser.parse_args()
    return options


# broadcasting request to get answer from each one
# with his IP and his mac for further attack
# and putting it in object
def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clients_list = []
    for element in answered_list:
        clients_dic = {'ip': element[1].psrc, 'mac': element[1].hwsrc}
        clients_list.append(clients_dic)
    return clients_list


# printing object in table form in terminal
def print_result(results_list):
    print('IP\t\t\t AT MAC \n************************************************')
    for client in results_list:
        print(client["ip"] + '\t\t' + client["mac"])


option = get_arguments()
scan_results = scan(option.target)
print_result(scan_results)
# '10.0.2.0/24'

# this file will simply send arp request on the whole network
# to ask  every one about his IP and MAC address for further attacks.
