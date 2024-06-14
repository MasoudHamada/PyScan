import subprocess
import re
import sys
import threading
import time
import os

def run_nmap_scan(ip):
    # Run the Nmap scan with the provided IP
    cmd = ['sudo', 'nmap', ip, '-p-', '-A', '-sV', '-v', '-T4']
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return result.stdout
    except subprocess.TimeoutExpired:
        print("Nmap scan timed out")
        return None
    except subprocess.CalledProcessError as e:
        print(f"Nmap scan failed: {e}")
        return None

def parse_nmap_output(output):
    data = {}
    if not output:
        return data

    # Extract open ports and services
    data['open_ports'] = re.findall(r'(\d+/tcp)\s+open\s+(\S+)\s+(\S+)', output)
    
    # Extract SSH Host Key Fingerprints
    ssh_hostkey_section = re.search(r'\|\s+ssh-hostkey:(.*?)\|_', output, re.DOTALL)
    if ssh_hostkey_section:
        data['ssh_hostkeys'] = re.findall(r'\|\s+(\d+)\s+(\S+)', ssh_hostkey_section.group(1))

    # Extract HTTP Server details
    http_server_header = re.search(r'\|\s+http-server-header:\s+(.*)', output)
    http_title = re.search(r'\|\s+http-title:\s+(.*)', output)
    http_methods = re.search(r'\|\s+http-methods:\s+\n\|\s+Supported Methods:\s+(.*)', output)
    if http_server_header or http_title or http_methods:
        data['http_details'] = {
            'server_header': http_server_header.group(1) if http_server_header else None,
            'title': http_title.group(1) if http_title else None,
            'methods': http_methods.group(1) if http_methods else None
        }
    
    # Extract OS detection details
    os_detection = re.search(r'No exact OS matches for host (.*?)(?=TCP/IP fingerprint:)', output, re.DOTALL)
    if os_detection:
        data['os_details'] = os_detection.group(1).strip()
    
    # Extract uptime
    uptime = re.search(r'Uptime guess: (.*)', output)
    if uptime:
        data['uptime'] = uptime.group(1)
    
    # Extract network distance
    network_distance = re.search(r'Network Distance: (\d+) hops', output)
    if network_distance:
        data['network_distance'] = network_distance.group(1)
    
    # Extract traceroute details
    traceroute_section = re.search(r'TRACEROUTE \((.*?)\)\n(.*?)\n\n', output, re.DOTALL)
    if traceroute_section:
        hops = re.findall(r'(\d+)\s+(\d+\.\d+ ms)\s+(\S+)', traceroute_section.group(2))
        data['traceroute'] = hops

    return data

def format_output(data):
    if not data:
        return "No data to display"

    formatted = "Nmap Scan Results:\n\n"

    # Format open ports and services
    if 'open_ports' in data:
        formatted += "Open Ports and Services:\n"
        for port, state, service in data['open_ports']:
            formatted += f"  - Port: {port}, State: {state}, Service: {service}\n"
    
    # Format SSH Host Key Fingerprints
    if 'ssh_hostkeys' in data:
        formatted += "\nSSH Host Key Fingerprints:\n"
        for bits, fingerprint in data['ssh_hostkeys']:
            formatted += f"  - {bits} bits: {fingerprint}\n"
    
    # Format HTTP Server details
    if 'http_details' in data:
        formatted += "\nHTTP Server Details:\n"
        http = data['http_details']
        formatted += f"  - Server Header: {http['server_header']}\n" if http['server_header'] else ""
        formatted += f"  - Title: {http['title']}\n" if http['title'] else ""
        formatted += f"  - Supported Methods: {http['methods']}\n" if http['methods'] else ""
    
    # Format OS detection details
    if 'os_details' in data:
        formatted += f"\nOS Details: {data['os_details']}\n"
    
    # Format uptime
    if 'uptime' in data:
        formatted += f"\nUptime Guess: {data['uptime']}\n"
    
    # Format network distance
    if 'network_distance' in data:
        formatted += f"\nNetwork Distance: {data['network_distance']} hops\n"
    
    # Format traceroute details
    if 'traceroute' in data:
        formatted += "\nTraceroute:\n"
        for hop, rtt, address in data['traceroute']:
            formatted += f"  - Hop {hop}: {rtt}, Address: {address}\n"

    return formatted

def radar_animation(stop_event):
    while not stop_event.is_set():
        for symbol in '|/-\\':
            sys.stdout.write(f'\rScanning... {symbol}')
            sys.stdout.flush()
            time.sleep(0.1)
    sys.stdout.write('\rScan complete.    \n')

def create_directory_structure(ip, formatted_output, data):
    # Create a directory with the IP address
    if not os.path.exists(ip):
        os.makedirs(ip)
    
    # Save the scan output to a text file
    with open(os.path.join(ip, 'initial_scan.txt'), 'w') as f:
        f.write(formatted_output)
    
    # Create directories for each open port
    if 'open_ports' in data:
        for port, state, service in data['open_ports']:
            port_dir = f"{port.split('/')[0]}_{service}"
            os.makedirs(os.path.join(ip, port_dir), exist_ok=True)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 pyscan.py <IP>")
        sys.exit(1)

    ip = sys.argv[1]

    stop_event = threading.Event()
    animation_thread = threading.Thread(target=radar_animation, args=(stop_event,))
    animation_thread.start()

    nmap_output = run_nmap_scan(ip)
    stop_event.set()
    animation_thread.join()

    parsed_data = parse_nmap_output(nmap_output)
    formatted_output = format_output(parsed_data)
    print(formatted_output)

    create_directory_structure(ip, formatted_output, parsed_data)
