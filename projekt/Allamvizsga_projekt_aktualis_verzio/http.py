from scapy.all import *
import json



def sniff_http_ftp_packets(iface):
	sniff(iface=iface, prn=process_http_ftp_packet, store=0)
	
# Function to process HTTP packets
def process_http_ftp_packet(packet):
	if packet.haslayer(TCP):
		if packet[TCP].dport == 80 or packet[TCP].sport == 80:  # Filter HTTP packets
			if packet.haslayer(Raw):  # Check if there's raw data (HTTP payload)
				http_payload = packet[Raw].load.decode('utf-8', 'ignore')  # Decode HTTP payload
				from ui import http_queue
				http_queue.put((http_payload, 1))
				print("HTTP Payload:")
				print(http_payload)
				print("=" * 50)
				
		if packet[TCP].dport == 21 or packet[TCP].sport == 21:  # Filter FTP control packets (port 21)
			if packet.haslayer(Raw):  # Check if there's raw data (FTP payload)
				ftp_payload = packet[Raw].load.decode('utf-8', 'ignore')  # Decode FTP payload
				try:
					from ui import http_queue
					http_queue.put((ftp_payload, 2))
				except Exception as e:
					print(e)
				print("FTP Payload:")
				print(ftp_payload)
				print("=" * 50)


#sniff(iface='eth1', prn=process_http_ftp_packet, store=0)
