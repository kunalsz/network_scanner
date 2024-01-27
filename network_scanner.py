"""
Network Scanner
Create arp request directed to broadcast mac asking for ip
    -use arp to ask who has target IP
    - set destination mac to broadcast mac such that arp request gets sent to all devices on the network
    -get vendor info from api
"""

import scapy.all as scapy #library to interact with networks
import argparse
import requests
import time

#get the manufacturer
def get_man(mac_add):
    r = requests.get(f'https://api.macvendors.com/{mac_add}')
    return r.text


#get args from command line
def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t','--target',dest='target',help='Target IP/IP ranges')
    options = parser.parse_args()

    if not options.target:
        print('Specify the target IP/IP ranges !')
    else:
        return options

#func to scan IP
def scan(ip):
    #scapy.arping(ip) #arp : lists all the devices connected with their ip and mac

    arp_request = scapy.ARP(pdst=ip) #set ARP object instance
    #print(arp_request.summary()) #get the summary of the ARP request sent
    #scapy.ls(scapy.ARP()) #get all the parameters you can set for arp_request

    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff') #make an ethernet object to send ARP packet,dest is set to all the mac address in the subnet
    arp_request_broadcast = broadcast/arp_request #combine broadcast and arp request
    #arp_request_broadcast.show() #see more details than summary

    answered,unanswered = scapy.srp(arp_request_broadcast,timeout=1,verbose=False) #send and recieve the final packet ; it returns two list answered packets(which contains 2 lists packets sent and answer) and unaswered packets list
    #print(answered.summary()) #see the answered packets

    #creating a dict for the data
    data = []
    for el in answered:
        clnt_dict = {'ip':el[1].psrc,'mac':el[1].hwsrc}
        data.append(clnt_dict)
    return data

#func to make table and display data
def show_data(res_list):
    #make a table
    print('IP\t\t\tMAC Adress\t\tVendor\n-----------------------------------------------------------')
    for el in res_list:
        time.sleep(1)
        print(el['ip'] + '\t\t' + el['mac'] + '\t' + get_man(el['mac']))

ip = get_args()

try:
    res_list = scan(ip.target)
    show_data(res_list)
except:
    pass

