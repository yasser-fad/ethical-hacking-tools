#!/usr/bin/env python3
import argparse
# scapy module allow us to use arp packet
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
    # create an arp request asking for an ip
    # to get the fields that can be used in scapy.arp use scapy.ls(scapy.ARP())
    arp_request = scapy.ARP(pdst=ip)
    #directed to the broadcast
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    #broadcast apending with the arp_request scapy allow to do that using /
    arp_request_broadcast = broadcast / arp_request
    #srp allow to send packet with a custome ether part or mac
    # srp used 2 methouds answered and unanswered
    #0 is to give me element 0 answereslist.
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
#client list is a big list that containe the dictionary elements{key,mac,ip}
    clients_list = []
    # loop to the answered element 
    for element in answered_list:
        #implementing the dictonary elements in the list
        # answered list has 2 element request send[0],req received[1]
        #the dictonary access using a keys 
        clients_dic = {'ip': element[1].psrc, 'mac': element[1].hwsrc}
        #append to put the dictoinry in the list
        clients_list.append(clients_dic)
        # what happends know for each element in answered list that has useful and non-useful infomation
        #create a dict that has 2 keys ip and mac 
        # add the values as elements to the big list client list 
    return clients_list


# printing object in table form in terminal
def print_result(results_list):
    #printing the headers
    print('IP\t\t\t AT MAC \n************************************************')
    for client in results_list:
        print(client["ip"] + '\t\t' + client["mac"])


option = get_arguments()
#calling the scanfunction that mak the big list and the dictionary
scan_results = scan(option.target)
#printing the resualt
print_result(scan_results)
# '10.0.2.0/24'

# this file will simply send arp request on the whole network
# to ask  every one about his IP and MAC address for further attacks.
