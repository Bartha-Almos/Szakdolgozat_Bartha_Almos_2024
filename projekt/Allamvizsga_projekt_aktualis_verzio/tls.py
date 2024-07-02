import tkinter as tk
from tkinter import scrolledtext, ttk, messagebox, simpledialog
from scapy.all import *
import queue
import subprocess
import json
import threading

# TLS dictionaries
tls_versions = {
	0x0300: "SSL 3.0",
	0x0301: "TLS 1.0",
	0x0302: "TLS 1.1",
	0x0303: "TLS 1.2",
	0x0304: "TLS 1.3"
}
	
tls_message_types = {
	0: "hello_request",
	1: "client_hello",
	2: "server_hello",
	4: "new_session_ticket",
	5: "end_of_early_data",
	6: "hello_retry_request",
	8: "encrypted_extensions",
	11: "certificate",
	12: "server_key_exchange",
	13: "certificate_request",
	14: "server_hello_done",
	15: "certificate_verify",
	16: "client_key_exchange",
	20: "finished",
	21: "certificate_url",
	22: "certificate_status",
	23: "supplemental_data",
	24: "key_update",
	25: "compressed_certificate",
	26: "encrypted_client_hello",
	254: "message_hash",
	255: "hello_retry_request"
}

def sniff_tls_packets(iface):
	load_layer('tls')
	sniff(iface=iface, prn=process_tls_packet, store=0)

def process_tls_packet(packet):
	if TLS in packet:
		tls = packet[TLS]
		if tls.type == 22:
			# Initialize the fields
			mtype = "N/A"
			version = "N/A"
			servername = "N/A"
			algorithms = "N/A"

			# Try to get the message type
			try:
				mtype_num = tls[1].msgtype
				mtype = tls_message_types.get(mtype_num, f"Unknown ({mtype_num})")
			except Exception as e:
				print(f"could not get msgtype: {e}")

			# Try to get the version
			try:
				version_num = tls[1].version
				version = tls_versions.get(version_num, f"Unknown ({version_num})")
			except Exception as e:
				print(f"could not get version: {e}")

			# Try to get the server name
			try:
				servername = str(tls[1][1].servernames)
			except Exception as e:
				print(f"could not get server name: {e}")

			# Try to get the signature algorithms
			try:
				algorithms = repr(tls[1][18])
			except Exception as e:
				print(f"could not get signature algorithm: {e}")

			# Combine the fields into one string
			combined_info = f"Message Type: {mtype}, Version: {version}, Server Name: {servername}, Signature Algorithms: {algorithms}"
			print(combined_info)
			# Add the packet info to the queue
			from ui import tls_queue
			tls_queue.put((combined_info, mtype_num))
