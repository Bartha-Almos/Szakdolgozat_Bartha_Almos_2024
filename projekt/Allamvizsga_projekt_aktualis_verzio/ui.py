import tkinter as tk
from tkinter import scrolledtext, ttk, messagebox, simpledialog
from scapy.all import *
import queue
import subprocess
import json
import threading
from ntp import *
from dns import *
from tls import *
from http import *

load_layer('tls')
# Global packet queue to be shared between files
packet_queue = queue.Queue()
tls_queue = queue.Queue()
http_queue = queue.Queue()
ftp_queue = queue.Queue()

# File path for saving hostDict
host_dict_file = "host_dict.json"

# Load hostDict
def load_host_dict():
    try:
        with open(host_dict_file, 'r') as file:
            global hostDict
            hostDict = json.load(file)
            # Convert keys from str to bytes
            hostDict = {key.encode(): value for key, value in hostDict.items()}
            print("Loaded hostDict from file.")
    except FileNotFoundError:
        print("No previous hostDict file found. Starting with empty hostDict.")
    except json.JSONDecodeError as e:
        print(f"Error loading hostDict file: {e}")

# Save hostDict
def save_host_dict():
    try:
        # Convert keys from bytes to str
        hostDict_str_keys = {key.decode(): value for key, value in hostDict.items()}
        with open(host_dict_file, 'w') as file:
            json.dump(hostDict_str_keys, file, indent=4)
            print("hostDict saved to file.")
    except Exception as e:
        print(f"Error saving hostDict to file: {e}")



# PacketSnifferUI class definition
class PacketSnifferUI:
	def __init__(self, root, stop_event):
		self.root = root
		self.stop_event = stop_event
		self.root.title("DNS and NTP Packet Sniffer and Modifier")
	
		top_frame = tk.Frame(root)
		top_frame.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)
	
		# Frame for the interface selections and labels
		iface_frame1 = tk.Frame(top_frame)
		iface_frame1.pack(side=tk.LEFT, padx=5, pady=5)
	
		self.iface_label1 = tk.Label(iface_frame1, text="Select Interface for kartya1:")
		self.iface_label1.pack(side=tk.TOP, padx=5, pady=5)
	
		self.iface_combobox1 = ttk.Combobox(iface_frame1)
		self.iface_combobox1.pack(side=tk.TOP, padx=5, pady=5)
		self.update_interfaces(self.iface_combobox1)
	
		iface_frame2 = tk.Frame(top_frame)
		iface_frame2.pack(side=tk.LEFT, padx=5, pady=5)
	
		self.iface_label2 = tk.Label(iface_frame2, text="Select Interface for kartya2:")
		self.iface_label2.pack(side=tk.TOP, padx=5, pady=5)
	
		self.iface_combobox2 = ttk.Combobox(iface_frame2)
		self.iface_combobox2.pack(side=tk.TOP, padx=5, pady=5)
		self.update_interfaces(self.iface_combobox2)
	
		self.start_button = tk.Button(top_frame, text="Start Sniffing", command=self.start_sniffing)
		self.start_button.pack(side=tk.LEFT, padx=5, pady=5)
	
		self.cut_dns_button = tk.Button(top_frame, text="Cut DNS Traffic", command=self.cut_dns_traffic)
		self.cut_dns_button.pack(side=tk.LEFT, padx=5, pady=5)
	
		self.stop_spoof_button = tk.Button(top_frame, text="Stop DNS Spoof", command=self.stop_dns_spoof)
		self.stop_spoof_button.pack(side=tk.LEFT, padx=5, pady=5)
	
		self.exit_button = tk.Button(top_frame, text="Exit", command=self.exit_program)
		self.exit_button.pack(side=tk.RIGHT, padx=5, pady=5)
	
		# Buttons for hostDict management
		self.manage_dict_frame = tk.Frame(root)
		self.manage_dict_frame.pack(padx=5, pady=5)
	
		self.add_dict_button = tk.Button(self.manage_dict_frame, text="Add to hostDict", command=self.add_to_dict)
		self.add_dict_button.grid(row=0, column=0, padx=5, pady=5)
	
		self.remove_dict_button = tk.Button(self.manage_dict_frame, text="Remove from hostDict", command=self.remove_from_dict)
		self.remove_dict_button.grid(row=0, column=1, padx=5, pady=5)
	
		self.update_dict_button = tk.Button(self.manage_dict_frame, text="Update hostDict", command=self.update_dict)
		self.update_dict_button.grid(row=0, column=2, padx=5, pady=5)
	
		# Add buttons for NTP changes
		self.ntp_start_button = tk.Button(top_frame, text="Start NTP Change", command=self.start_ntp_change)
		self.ntp_start_button.pack(side=tk.LEFT, padx=5, pady=5)
	
		self.ntp_stop_button = tk.Button(top_frame, text="Stop NTP Change", command=self.stop_ntp_change)
		self.ntp_stop_button.pack(side=tk.LEFT, padx=5, pady=5)
	
		self.text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=120, height=30)
		self.text_area.pack(padx=5, pady=5)
	
		self.update_text_periodically()
		
		self.update_tls_text_periodically()
	
		# Add button for TLS sniffing
		self.start_tls_button = tk.Button(top_frame, text="Start TLS Sniffing", command=self.start_tls_sniffing)
		self.start_tls_button.pack(side=tk.LEFT, padx=5, pady=5)
		
		self.start_http_button = tk.Button(top_frame, text="Start HTTP and FTP Sniffing", command=self.start_http_sniffing)
		self.start_http_button.pack(side=tk.LEFT, padx=5, pady=5)
		self.update_http_text_periodically()
	
	def update_interfaces(self, combobox):
		interfaces = get_if_list()
		combobox['values'] = interfaces
		combobox.set('')  # Clear current selection
	
	def start_sniffing(self):
		load_host_dict()
		iface1 = self.iface_combobox1.get()
		iface2 = self.iface_combobox2.get()
	
		if not iface1:
			iface1 = 'eth1'  # Default if no interface is selected
		if not iface2:
			iface2 = 'eth0'  # Default if no interface is selected
	
		self.start_packet_sniffing_threads(iface1, iface2, hostDict)
	
	def start_packet_sniffing_threads(self, iface1, iface2, hostDict):
		from main import start_sniffing_threads
		start_sniffing_threads(iface1, iface2, hostDict, self.stop_event)
	
	def cut_dns_traffic(self):
		try:
			subprocess.run(["sudo", "ebtables", "-A", "FORWARD", "-p", "IPv4", "--ip-protocol", "udp", "--ip-sport", "53", "-j", "DROP"], check=True)
			subprocess.run(["sudo", "ebtables", "-A", "FORWARD", "-p", "IPv4", "--ip-protocol", "udp", "--ip-dport", "53", "-j", "DROP"], check=True)
			self.update_text("DNS traffic has been cut off.")
		except subprocess.CalledProcessError as e:
			self.update_text(f"Failed to cut DNS traffic: {e}")

	def stop_dns_spoof(self):
		try:
			subprocess.run(["sudo", "ebtables", "-D", "FORWARD", "-p", "IPv4", "--ip-protocol", "udp", "--ip-sport", "53", "-j", "DROP"], check=True)
			subprocess.run(["sudo", "ebtables", "-D", "FORWARD", "-p", "IPv4", "--ip-protocol", "udp", "--ip-dport", "53", "-j", "DROP"], check=True)
			self.update_text("DNS spoof has been stopped.")
		except subprocess.CalledProcessError as e:
			self.update_text(f"Failed to stop dns spoof: {e}")
	
	def exit_program(self):
		try:
			self.stop_dns_spoof()
		except Exception as e:
			print(e)
		try:
			self.stop_ntp_change()
		except Exception as e:
			print(e)
		self.stop_event.set()
		self.root.quit()

	def update_text(self, packet_info, modified=False, is_response=False):
		if modified:
			self.text_area.insert(tk.END, f"MODIFIED: {packet_info}\n", "modified")
			self.text_area.tag_config("modified", background="yellow", foreground="red")
		elif is_response:
			self.text_area.insert(tk.END, packet_info + "\n", "response")
			self.text_area.tag_config("response", foreground="blue")
		else:
			self.text_area.insert(tk.END, packet_info + "\n", "request")
			self.text_area.tag_config("request", foreground="green")
		self.text_area.see(tk.END)
        
	def update_text_tls(self, packet_info, msgtype):
		if msgtype == 1:
			self.text_area.insert(tk.END, packet_info + "\n", "request")
			self.text_area.tag_config("request", foreground="green")
		elif msgtype == 2:
			self.text_area.insert(tk.END, packet_info + "\n", "response")
			self.text_area.tag_config("response", foreground="blue")
		else:
			self.text_area.insert(tk.END, packet_info + "\n", "request")
			self.text_area.tag_config("request", foreground="gray")
		self.text_area.see(tk.END)
		
	def update_text_http(self, packet_info, msgtype):
		if msgtype == 1:
			self.text_area.insert(tk.END, packet_info + "\n", "http")
			self.text_area.tag_config("request", foreground="green")
		elif msgtype == 2:
			self.text_area.insert(tk.END, packet_info + "\n", "ftp")
			self.text_area.tag_config("response", foreground="blue")
		else:
			self.text_area.insert(tk.END, packet_info + "\n", "request")
			self.text_area.tag_config("request", foreground="gray")
		self.text_area.see(tk.END)      
	
	def process_packet_queue(self):
		while not packet_queue.empty():
			packet_info, modified, is_response = packet_queue.get()
			self.update_text(packet_info, modified, is_response)
			
	def process_tls_queue(self):
		while not tls_queue.empty():
			packet_info, msgtype = tls_queue.get()
			self.update_text_tls(packet_info, msgtype)
	
	def update_text_periodically(self):
		self.process_packet_queue()
		self.root.after(100, self.update_text_periodically)
		
	def process_http_queue(self):
		while not http_queue.empty():
			packet_info, msgtype = http_queue.get()
			self.update_text_http(packet_info, msgtype)
	
	def update_http_text_periodically(self):
		self.process_http_queue()
		self.root.after(100, self.update_http_text_periodically)
	
	def update_tls_text_periodically(self):
		self.process_tls_queue()
		self.root.after(100, self.update_tls_text_periodically)
	
	def add_to_dict(self):
		query_name = simpledialog.askstring("Add to hostDict", "Enter DNS query name:")
		if query_name:
			ip_address = simpledialog.askstring("Add to hostDict", f"Enter IP address for {query_name}:")
			if ip_address:
				hostDict[query_name.encode()] = ip_address
				self.update_text(f"Added b'{query_name}': {ip_address} to hostDict.")
				save_host_dict()  # Save hostDict after modification
	
	def remove_from_dict(self):
		query_name = simpledialog.askstring("Remove from hostDict", "Enter DNS query name to remove:")
		if query_name and query_name.encode() in hostDict:
			del hostDict[query_name.encode()]
			self.update_text(f"Removed b'{query_name}' from hostDict.")
			save_host_dict()  # Save hostDict after modification
		else:
			messagebox.showwarning("Error", "DNS query name not found in hostDict.")
	
	def update_dict(self):
		query_name = simpledialog.askstring("Update hostDict", "Enter DNS query name to update:")
		if query_name and query_name.encode() in hostDict:
			new_ip_address = simpledialog.askstring("Update hostDict", f"Enter new IP address for {query_name}:")
			if new_ip_address:
				hostDict[query_name.encode()] = new_ip_address
				self.update_text(f"Updated b'{query_name}' to {new_ip_address} in hostDict.")
				save_host_dict()  # Save hostDict after modification
		else:
			messagebox.showwarning("Error", "DNS query name not found in hostDict.")
	
	def start_ntp_change(self):
		try:
			subprocess.run(["sudo", "ebtables", "-A", "FORWARD", "-p", "IPv4", "--ip-protocol", "UDP", "--ip-sport", "123", "-j", "DROP"], check=True)
			subprocess.run(["sudo", "ebtables", "-A", "FORWARD", "-p", "IPv4", "--ip-protocol", "UDP", "--ip-dport", "123", "-j", "DROP"], check=True)
			messagebox.showinfo("Info", "NTP Change Started")
		except subprocess.CalledProcessError as e:
			messagebox.showerror("Error", f"Failed to start NTP change: {e}")
	
	def stop_ntp_change(self):
		try:
			subprocess.run(["sudo", "ebtables", "-D", "FORWARD", "-p", "IPv4", "--ip-protocol", "UDP", "--ip-sport", "123", "-j", "DROP"], check=True)
			subprocess.run(["sudo", "ebtables", "-D", "FORWARD", "-p", "IPv4", "--ip-protocol", "UDP", "--ip-dport", "123", "-j", "DROP"], check=True)
			messagebox.showinfo("Info", "NTP Change Stopped")
		except subprocess.CalledProcessError as e:
			messagebox.showerror("Error", f"Failed to stop NTP change: {e}")
	
	def start_tls_sniffing(self):
		# Stop other sniffing processes
		self.stop_dns_spoof()
		self.stop_event.set()
	
		# Start TLS sniffing
		iface1 = self.iface_combobox1.get()
		iface2 = self.iface_combobox2.get()
	
		if not iface1:
			iface1 = 'eth1'  # Default if no interface is selected
		if not iface2:
			iface2 = 'eth0'  # Default if no interface is selected
	
		thread = threading.Thread(target=sniff_tls_packets, args=(iface1,))
		thread.start()
		
	def start_http_sniffing(self):
		# Stop other sniffing processes
		self.stop_dns_spoof()
		self.stop_ntp_change()
		self.stop_event.set()
	
		# Start TLS sniffing
		iface1 = self.iface_combobox1.get()
		iface2 = self.iface_combobox2.get()
	
		if not iface1:
			iface1 = 'eth1'  # Default if no interface is selected
		if not iface2:
			iface2 = 'eth0'  # Default if no interface is selected
	
		thread = threading.Thread(target=sniff_http_ftp_packets, args=(iface1,))
		thread.start()
	
	# def star_dns_thread(self):
		# dns_t1 = threading.Thread(target=dns_resp, args=(iface1, iface2, stop_event, hostDict))
		# dns_t2 = threading.Thread(target=dns_query, args=(iface1, iface2, stop_event, hostDict))
		
		# dns_t1.start()
		# dns_t2.start()
		
	# def start_ntp_thread(self):
		# ntp_t1 = threading.Thread(target=ntp_kartya1, args=(iface1, iface2, stop_event, hostDict))
		# ntp_t2 = threading.Thread(target=ntp_kartya2, args=(iface1, iface2, stop_event, hostDict))
		
		# ntp_t1.start()
		# ntp_t2.start()

def run_ui(stop_event):
    load_host_dict()
    root = tk.Tk()
    app = PacketSnifferUI(root, stop_event)
    root.mainloop()
    save_host_dict()

