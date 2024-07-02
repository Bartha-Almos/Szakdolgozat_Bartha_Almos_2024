#!/bin/python3

import threading
from scapy.all import*

#conf.logLevel = 0

def kartya1():
	print('kartya 1 mukszik')
	eth0mac=get_if_hwaddr("eth0")
	eth1mac=get_if_hwaddr("eth1")
	linksysmac='24:f5:a2:28:95:e0'
	pcmac='14:cc:20:05:c2:22'
	outbuff=[]
	while True:
		pkt=sniff(iface="eth1",filter="udp and port 53",store=1,count=1)
		packet=pkt[0]
#			packet[IP].dst = '8.8.8.8'
			#if hasattr(packet[DNS].an, 'rdata'):
		#	if 1==1:
#		#		packet[DNS].an.rdata = "8.8.8.8"
		#		packet[DNS].an = DNSRR(rrname='dns.google',ttl=10,type='A',rdata='8.8.8.8')
		#		packet[DNS].ancount = 1
		#		packet[DNS].qr = 1
		if DNSRR in packet:
			try:
				#packet[DNSRR].rdata = '8.8.8.8'
				print("Modified DNS querry:")
			except:
				print("Unable to modify response")
				packet.show()   
			try:      
				del packet[UDP].len    
				del packet[UDP].chksum
			except:
				print("skiping UDP chksum calc")
			try:      
				del packet[IP].len
				del packet[IP].chksum
			except:
				print("skiping IP chksum calc")
		try:
			sendp(packet,iface="eth0",verbose=0,count=1)
		except:
			packet.show()
			print("Nem tudja elkuldeni")
		del packet
		#outbuff+=pkt[:]
		#for src in outbuff[:]:
		#	srcmac=src.sprintf(r"%Ether.src%")
		#	sendp(src,iface="enp0s8",verbose=0)

def kartya2():
	print('kartya 2 mukszik')
	eth0mac=get_if_hwaddr("eth0")
	eth1mac=get_if_hwaddr("eth1")
	linksysmac='24:f5:a2:28:95:e0'
	pcmac='14:cc:20:05:c2:22'
	outbuff=[]
	while True:
		pkt=sniff(iface="eth0",filter="udp and port 53",store=1,count=1)
		#print("Eredeti csomag")
		# pkt[0].show()
		#if pkt[0].dst != 'ff:ff:ff:ff:ff:ff':
		#	pkt[0].dst=linksysmac
		#pkt[0].src=eth1mac
		#try:      
		#	del packet[UDP].len    
		#	del packet[UDP].chksum
		#except:
			#print("skiping UDP chksum calc")
		#try:      
		#	del packet[IP].len
		#	del packet[IP].chksum
		#except:
			#print("skiping IP chksum calc")
		#if pkt[0].src == '08:00:27:9f:2b:75':
		#	pkt[0].src=mac1
		#print("Eredeti csomag")
		#pkt[0].show()
		
		#ha a DNS keresben szerelo nev benne van a listankban, akkor keszitunk egy uj kerest es azt kuldjuk el
		#az eredeti keres nem lesz elkuldve a szerver fele.
		try:
			sendp(pkt,iface="eth1",verbose=0,count=1)
		except:
			pkt[0].show()
			print("Nem tudta elkuldeni")
		del pkt
		#outbuff+=pkt[:]
		#for src in outbuff[:]:
		#	srcmac=src.sprintf(r"%Ether.src%")
		#	sendp(src,iface="enp0s3",verbose=0)

if __name__=="__main__":
	t1= threading.Thread(target=kartya1)
	t2= threading.Thread(target=kartya2)

	t1.start()
	t2.start()

	t1.join()
	t2.join()

	print('vege')
