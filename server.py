from scapy.all import *
from notif import balloon_tip
import os
ip_pck_count = {}

clients = []
with open("clients.csv", 'r') as clientsfile:
    clients = clientsfile.read().split(',')

print (clients) 

def sendalert(client, ip):
    message = "Attacker:"+str(ip)
    packet = IP(dst=client)/ICMP()/message
    count = 0
    while count < 10:
        send(packet)
        count = count +1

def pkt_callback(pkt):
    if  str(pkt.getlayer(ICMP).type) == "8": #for ping
        ip = pkt[IP].src
        if ip not in ip_pck_count:
            ip_pck_count[ip] = 1
        else:
            ip_pck_count[ip] = ip_pck_count[ip] + 1 

        if(ip_pck_count[ip]==4):
            balloon_tip('Attacker Spotted','Your PC is being attacked by'+str(ip))
            for client in clients:
                sendalert(client, ip)
            exit()    


sniff(prn=pkt_callback, filter="icmp", store=0)