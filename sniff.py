from scapy.all import *
import os
ip_pck_count = {}

def pkt_callback(pkt):
    if  str(pkt.getlayer(ICMP).type) == "8": #for ping
        ip = pkt[IP].src
        if ip not in ip_pck_count:
        	ip_pck_count[ip] = 1
        else:
        	ip_pck_count[ip] = ip_pck_count[ip] + 1	

        if(ip_pck_count[ip]==4):
        	print("Attacker spotted! 4 pings : " + ip)
        	command = "python attack.py "+str(ip)+" 1.1.1.1"
        	os.system (command)


sniff(prn=pkt_callback, filter="icmp", store=0)