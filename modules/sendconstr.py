import platform, subprocess, socket, ipaddress, time, threading, datetime as dt
from scapy.all import srp, sendp
from scapy.layers.l2 import Ether, ARP
from concurrent.futures import ThreadPoolExecutor
from random import randint

def icmp_ping(ip):
    """Ping an IP address and return True if online, False otherwise."""
    param = '-n' if platform.system().lower() == 'windows' else '-c' # Windows uses -n, Linux uses -c
    # Construct the ping command
    command = ['ping', param, '1', str(ip)]
    
    try:
        # Execute the ping command and capture the output
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        # Check the output for keywords indicating success or failure
        if any(keyword in result.stdout.lower() for keyword in ["unreachable", "timed out", "failure"]):
            return False
        return True
    except Exception as e:
        # Handle any exceptions that occur during the ping process
        print(f"Error pinging {ip}: {e}")
        return False
    
# function to check if an ip address is online using ARP
def arp_check(ip):
    """Send an ARP request to the specified IP and check for a response."""
    try:
        # Construct the ARP request packet
        arp_request = ARP(pdst=str(ip))
        ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether_frame / arp_request

        # Send the packet and wait for a response
        answered, unanswered = srp(packet, timeout=3, verbose=False)

        # Process the responses
        for sent, received in answered:
            if received and received.op == 2:  # ARP reply
                return received.hwsrc  # Return the MAC address

        return False  # No response
    except Exception as e:
        # handle exceptions
        print(f"Error in ARP check for {ip}: {e}")
        return False
    
# function to check if a device is online by connecting to common ports
def check_ports(ip, ports=[20, 21, 22, 23, 25, 53, 80, 443, 3389, 8080]):
    for port in ports:
        if check_port(ip, port):
            print(f"{ip} is online (port {port} responding).")
            return True
    return False

def check_port(ip, port):
    """Check if a specific port is open on an IP address."""
    try:
        with socket.create_connection((str(ip), port), timeout=3):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False

# function to scan a specific IP address and check its status

def scan_subnet(subnet_str, ports):
    """Scan all IPs in the specified subnet."""
    global devices
    subnet = ipaddress.IPv4Network(subnet_str, strict=False)

    executor = ThreadPoolExecutor(max_workers=100)
    #for ip in subnet.hosts():
        #executor.submit(, ip, ports)
    #return executor
