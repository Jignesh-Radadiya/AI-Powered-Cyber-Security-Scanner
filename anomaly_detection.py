### anomaly_detection.py - Advanced Live Traffic Anomaly Detection ####



import tkinter as tk
from tkinter import scrolledtext
from tkinter import filedialog
import joblib
import pandas as pd
import numpy as np
import scapy.all as scapy
import threading
import time
import ssl
import OpenSSL
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.tls.all import TLS, TLSClientHello
from sklearn.preprocessing import StandardScaler
from scapy.utils import rdpcap
from decimal import Decimal  # Import Decimal if necessary for precise handling
import hashlib






# Check if MAC address belongs to VMware (OUI prefixes)
def check_vmware_mac(mac_address):
    # VMware MAC address OUI prefixes
    vmware_oui = ["00:50:56", "00:0C:29", "00:1C:42"]
    # Check if MAC starts with any of the VMware OUI prefixes
    return any(mac_address.startswith(oui) for oui in vmware_oui)
    
# Generate MD5 & SHA-256 hash of packet payload
def generate_hashes(payload):
    md5_hash = hashlib.md5(payload).hexdigest() if payload else "N/A"
    sha256_hash = hashlib.sha256(payload).hexdigest() if payload else "N/A"
    return md5_hash, sha256_hash

# Generate a simple fingerprint of a packet
def fingerprint_packet(packet):
    data = bytes(packet)
    xor_hash = 0
    for byte in data:
        xor_hash ^= byte
    return hex(xor_hash)
    


# Calculate entropy of packet payload
def calculate_entropy(data):
    if not data:
        return 0
    from collections import Counter
    counter = Counter(data)
    probabilities = [count / len(data) for count in counter.values()]
    entropy = -sum(p * np.log2(p) for p in probabilities)
    return entropy

# Extract SNI (Server Name Indication) from TLS Client Hello packets
def extract_sni(packet):
    if packet.haslayer(TLSClientHello):
        for ext in packet[TLSClientHello].ext:
            if isinstance(ext, scapy.layers.tls.TLSExtServerName):
                return ext.servernames[0].servername.decode()
    return None



class AIAnomalyDetector(tk.Frame):
    """GUI for Live AI-Powered Anomaly Detection."""
    
    def __init__(self, parent):
        super().__init__(parent, bg="#1e1e1e")
        self.parent = parent
        self.pack(fill="both", expand=True)  # Ensure it's packed to the parent frame
        
        # Title
        self.label = tk.Label(self, text="⚠️ Live Anomaly Detection", font=("Arial", 16, "bold"), bg="#1e1e1e", fg="#ff5555")
        self.label.pack(pady=10)
        
        
        

        # Display Output (Scrollable Text Area)
        self.text_area = scrolledtext.ScrolledText(self, width=80, height=20, font=("Arial", 12), bg="#2b2b2b", fg="#ffffff", insertbackground="#ffffff")
        self.text_area.pack(pady=10)

        # Start & Stop Buttons
        self.start_button = tk.Button(self, text="▶ Start Detection", command=self.start_detection, bg="#444", fg="#ffffff")
        self.start_button.pack(pady=5)

        self.stop_button = tk.Button(self, text="⏹ Stop Detection", command=self.stop_detection, bg="#444", fg="#ffffff", state="disabled")
        self.stop_button.pack(pady=5)

        # Save Button
        self.save_button = tk.Button(self, text="💾 Save Report", command=self.save_report, bg="#444", fg="#ffffff", state="disabled")
        self.save_button.pack(pady=5)
        
        
        
        

        # Load AI Model & Scaler
        try:
            self.model = joblib.load("ai_anomaly_model.pkl")  # Load trained model
            self.scaler = joblib.load("scaler.pkl")  # Load scaler correctly
        except Exception as e:
            self.text_area.insert(tk.END, f"❌ Error loading AI model: {e}\n")
            return

        self.running = False  # Control flag for real-time capture
        
       
    

    def start_detection(self):
        """Start Live Network Traffic Anomaly Detection."""
        self.running = True
        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.save_button.config(state="normal")  # Enable Save button once detection starts
        self.text_area.insert(tk.END, "✅ Live Anomaly Detection Started...\n")
        
        # Run packet capture in a separate thread
        threading.Thread(target=self.capture_packets, daemon=True).start()

    def stop_detection(self):
        """Stop Live Anomaly Detection."""
        self.running = False
        self.start_button.config(state="normal")
        self.stop_button.config(state="disabled")
        self.text_area.insert(tk.END, "⏹ Detection Stopped.\n")

    def capture_packets(self):
        """Capture network packets and analyze anomalies."""
        self.text_area.insert(tk.END, "📡 Capturing network traffic...\n")
        
        while self.running:
            try:
                packets = scapy.sniff(count=25, timeout=5)  # Capture 25 packets in 5 seconds
                for packet in packets:
                    features = self.extract_features(packet)
                    if features is not None:
                        self.analyze_packet(packet, features)
            except Exception as e:
                self.after(0, self.text_area.insert, tk.END, f"⚠️ Error: {e}\n")
                self.after(0, self.text_area.see, tk.END)  # Auto-scroll to latest log
            time.sleep(5)

    def extract_features(self, packet):
        """Extract features from a network packet."""
        try:
            if packet.haslayer(scapy.IP):
                return {
                    "flow_duration": len(packet),  
                    "total_fwd_packets": 1 if packet[scapy.IP].src else 0,  
                    "total_bwd_packets": 1 if packet[scapy.IP].dst else 0,  
                    "fwd_packet_length_max": len(packet.payload),  
                    "bwd_packet_length_max": len(packet.payload)
                }
        except Exception as e:
            self.after(0, self.text_area.insert, tk.END, f"❌ Feature Extraction Error: {e}\n")
        return None
        
    
    def analyze_packet(self, packet, features):
        """Predict if a packet is an anomaly using AI model."""
        try:
        
            df = pd.DataFrame([features])
            X_scaled = self.scaler.transform(df)
            prediction = self.model.predict(X_scaled)
            result = "🚨 Anomaly Detected!" if prediction[0] == -1 else "✅ Normal Traffic"
            packet_details = self.get_packet_details(packet)
            self.display_packet_result(result, packet_details, features)
        except Exception as e:
            self.after(0, self.text_area.insert, tk.END, f"⚠️ Prediction Error: {e}\n")
            
    
    

    def get_packet_details(self, packet):
        """Generate a detailed packet summary with advanced information."""
        details = []
        packet_payload = bytes(packet.payload)
        md5_hash, sha256_hash = generate_hashes(packet_payload)
        fingerprint = fingerprint_packet(packet)
        entropy = calculate_entropy(packet_payload)
        flags = []

        # Add flags based on entropy
        if entropy > 7.5:
            flags.append("⚠️ High Entropy - Possible Encryption or Malware")

    
        # Ethernet Layer
        if packet.haslayer(scapy.Ether):
            eth_src = packet[scapy.Ether].src
            eth_dst = packet[scapy.Ether].dst
            eth_type = packet[scapy.Ether].type
            details.append(f"Ethernet Layer: Source MAC: {eth_src}, Destination MAC: {eth_dst}, EthType: {hex(eth_type)}")
            
            # Check if the source MAC belongs to VMware
            if check_vmware_mac(eth_src):
                details.append(f"⚠️ VMware Virtual Machine detected based on MAC address: {eth_src}")
    
    
        # IP Layer
        if packet.haslayer(scapy.IP):
            ip_src = packet[scapy.IP].src
            ip_dst = packet[scapy.IP].dst
            ip_proto = packet[scapy.IP].proto
            ip_len = len(packet[scapy.IP])
            ttl = packet[scapy.IP].ttl
            ip_flags = packet[scapy.IP].flags
            ip_checksum = packet[scapy.IP].chksum
            details.append(f"IP Layer: Source IP: {ip_src}, Destination IP: {ip_dst}, Protocol: {ip_proto}, Length: {ip_len} bytes, TTL: {ttl}, Flags: {ip_flags}, Checksum: {ip_checksum}")
            
            
            # Guess OS based on TTL value
            os_guess = None
            if ttl == 64:
                os_guess = "Linux (possibly VM)"
            elif ttl == 128:
                os_guess = "Windows (possibly VM)"
            elif ttl == 255:
                os_guess = "FreeBSD"
            elif ttl == 64:
                os_guess = "MacOS"
            elif ttl == 254:
                os_guess = "Solaris"
            else:
                os_guess = "Unknown OS"
        
            if os_guess:
                details.append(f"Guessed OS based on TTL: {os_guess}")
            
            
    
        # TCP Layer
        if packet.haslayer(scapy.TCP):
            tcp_sport = packet[scapy.TCP].sport
            tcp_dport = packet[scapy.TCP].dport
            tcp_seq = packet[scapy.TCP].seq
            tcp_ack = packet[scapy.TCP].ack
            tcp_flags = packet[scapy.TCP].flags
            tcp_window_size = packet[scapy.TCP].window
            tcp_payload_len = len(packet[scapy.TCP].payload)
            tcp_options = packet[scapy.TCP].options
            details.append(f"TCP Layer: Source Port: {tcp_sport}, Destination Port: {tcp_dport}, Sequence: {tcp_seq}, Acknowledgment: {tcp_ack}, Flags: {tcp_flags}, Window Size: {tcp_window_size}, Payload Length: {tcp_payload_len}, Options: {tcp_options}")
            
         # TLS Handshake Detection (HTTPS SNI Extraction)
        if packet.haslayer(scapy.TCP) and packet[TCP].dport == 443:
            sni = extract_sni(packet)
            if sni:
                details.append(f"🌍 Website Visited (SNI): {sni}")
            else:
                details.append("🔍 No SNI found (Possibly Encrypted or QUIC)")
    
            
        # Check for SSL/TLS (Encrypted Traffic) Handshake
        if packet.haslayer(TCP) and packet.haslayer(scapy.Raw):
            if b"SSL" in packet[scapy.Raw].load or b"TLS" in packet[scapy.Raw].load:
                details.append(f"⚠️ SSL/TLS Traffic Detected")
    
        # UDP Layer
        elif packet.haslayer(scapy.UDP):
            udp_sport = packet[scapy.UDP].sport
            udp_dport = packet[scapy.UDP].dport
            udp_length = len(packet[scapy.UDP].payload)
            details.append(f"UDP Layer: Source Port: {udp_sport}, Destination Port: {udp_dport}, Payload Length: {udp_length}")
    
        # DNS Layer
        if packet.haslayer(scapy.DNS):
            try:
                dns_query = packet[scapy.DNS].qd.qname
                dns_type = packet[scapy.DNS].qd.qtype
                dns_response = packet[scapy.DNS].anc
                dns_response_details = ', '.join([str(record) for record in dns_response]) if dns_response else "No response"
                details.append(f"DNS Query: Domain: {dns_query}, Type: {dns_type}, Response: {dns_response_details}")
            except AttributeError:
                details.append("DNS Layer: Invalid DNS attributes")
                
                
    
        # HTTP-like Layer (Looking in raw payload for HTTP traffic)
        if packet.haslayer(scapy.Raw):
            raw_payload = packet[scapy.Raw].load.decode(errors="ignore")
            if "HTTP" in raw_payload:
                http_method = None
                http_host = None
                http_user_agent = None
                for line in raw_payload.split("\r\n"):
                    if line.startswith("GET") or line.startswith("POST"):
                        http_method = line.split(" ")[0]
                        details.append(f"HTTP Method: {http_method}")
                    elif line.startswith("Host:"):
                        http_host = line.split(":", 1)[1].strip()
                        details.append(f"HTTP Host: {http_host}")
                    elif line.startswith("User-Agent:"):
                        http_user_agent = line.split(":", 1)[1].strip()
                        details.append(f"HTTP User-Agent: {http_user_agent}")
         
        
                        
        # Add fingerprint, hashes, and entropy info
        details.append(f"🔑 Packet Fingerprint: {fingerprint}")
        details.append(f"🔍 MD5: {md5_hash}")
        details.append(f"🔍 SHA-256: {sha256_hash}")
        details.append(f"📊 Payload Entropy: {entropy:.2f}")
        if flags:
            details.append(f"🚩 Flags: {', '.join(flags)}")


        # Timestamp for when the packet was captured
        timestamp = packet.time
        details.append(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))}")

        return "\n".join(details)

    def display_packet_result(self, result, packet_details, features):
        """Display packet result with highlighted anomalies."""
        if result == "🚨 Anomaly Detected!":
            self.after(0, self.text_area.insert, tk.END, f"\n{result}\n", 'anomaly')
            self.after(0, self.text_area.insert, tk.END, f"Packet: {packet_details}\n", 'anomaly')
        else:
            self.after(0, self.text_area.insert, tk.END, f"\n{result}\n", 'normal')
            self.after(0, self.text_area.insert, tk.END, f"Packet: {packet_details}\n", 'normal')

        self.after(0, self.text_area.insert, tk.END, f"Features: {features}\n\n", 'normal')
        self.after(0, self.text_area.see, tk.END)  # Auto-scroll

        # Tags for colored text (anomalies in red, normal in green)
        self.text_area.tag_config('anomaly', foreground="#ff5555")
        self.text_area.tag_config('normal', foreground="#50fa7b")

    def save_report(self):
        """Save the report to a text file."""
        try:
            # Ask the user for a file path to save the report
            file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
            if file_path:
                with open(file_path, 'w') as f:
                    f.write(self.text_area.get("1.0", tk.END))  # Save all the text in the text_area
                self.text_area.insert(tk.END, f"✅ Report saved to {file_path}\n")
        except Exception as e:
            self.text_area.insert(tk.END, f"❌ Error saving report: {e}\n")
            

