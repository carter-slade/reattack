from scapy.all import *
import os

ip_pkt_count = {}
server_ip = '192.168.0.102'

def pkt_callback(pkt):
	if str(pkt.getlayer(ICMP).type) == "8":
		ip = pkt[IP].src
		if ip not in ip_pkt_count:
			ip_pkt_count[ip] = 1
		else:
			ip_pkt_count[ip] +=1
		print("IP of pinger:"+str(ip))
		if(ip_pkt_count[ip]==5 and ip==server_ip):
			print("5 pings received, Server under attack")
			print(pkt[Raw].load)
			exit()

sniff(prn=pkt_callback, filter="icmp", store = 0)
