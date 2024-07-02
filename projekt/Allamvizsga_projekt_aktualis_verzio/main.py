import threading
from scapy.all import sniff, sendp, Ether, IP, UDP, DNS, DNSRR, NTP, ProgPath, conf

from dns import *
from ntp import *

def start_sniffing_threads(iface1, iface2, stop_event, hostDict):
	dns_t1 = threading.Thread(target=dns_resp, args=(iface1, iface2, stop_event, hostDict))
	dns_t2 = threading.Thread(target=dns_query, args=(iface1, iface2, stop_event, hostDict))
	
	ntp_t1 = threading.Thread(target=ntp_kartya1, args=(iface1, iface2, stop_event, hostDict))
	ntp_t2 = threading.Thread(target=ntp_kartya2, args=(iface1, iface2, stop_event, hostDict))
	
	dns_t1.start()
	dns_t2.start()
	ntp_t1.start()
	ntp_t2.start()


	return dns_t1, dns_t2, ntp_t1, ntp_t2

if __name__ == "__main__":
	conf.prog.tcpreplay = '/usr/bin/tcpreplay'
	stop_event = threading.Event()
	from ui import run_ui
	run_ui(stop_event)
