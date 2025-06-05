from ipaddress import (
    IPv4Address, 
    IPv4Network,
    ip_address
)
from datetime import datetime as dt
from time import sleep
from random import uniform as rand

from concurrent.futures import ThreadPoolExecutor
from threading import (
    Lock,
    Thread,
    Event
)

# Scapy imports for dealing with packets
from scapy.packet import Packet
from scapy.all import rdpcap
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.netbios import (
    NBNSHeader,
    NBNSRegistrationRequest,
    NBNSNodeStatusRequest
)

from scapy.sendrecv import ( 
    send, 
    AsyncSniffer
)

# Host object
class Host:
    """
    Object to store information about a device because the creator doesn't want to use a dictionary and type 4 extra characters.

    Params:
        ip: string object representing the IP address of the host.
        mac: string object representing the MAC address of the host.
        last_seen: datetime object representing the last time the host was seen.
        hostname: string object representing the hostname of the host, defaults to "N/A".
        nbns: list of strings representing the NetBIOS names of the host, defaults to an empty list.
        mdns: list of strings representing the mDNS names of the host, defaults to an empty list.
        ports: list of integers representing the open ports of the host, defaults to an empty list.

    """
    def __init__(self, ip: str, mac: str, last_seen, hostname: str="N/A", nbns=None, mdns=None, ports=None):
        self.ip = ip
        self.mac = mac
        self.hostname = hostname
        self.nbns = nbns if nbns is not None else []
        self.mdns = mdns if mdns is not None else []
        self.ports = ports if ports is not None else []
        self.last_seen = last_seen
        self.notes = []

    def summary(self, output: bool=False):
        """
        Returns a summary of the host's information.
        """
        if output:
            print(f"{self.ip}  {self.mac}  {self.last_seen}    {self.hostname} | NBNS: {self.nbns} | mDNS: {self.mdns} | Ports: {self.ports}")
        else:
            return f"{self.ip}  {self.mac}  {self.last_seen}    {self.hostname} | NBNS: {self.nbns} | mDNS: {self.mdns} | Ports: {self.ports}"

class Parsers:
    @staticmethod
    def parse_mdns(packet):
        dns = packet[DNS]
        mdns = []
        notes = []
        if dns.qr == 1:
            # Answers
        
            def parse_answer(ans):
                rtype = ans.type

                try:
                    rrname = ans.rrname.decode().rstrip('.')
                except Exception:
                    rrname = str(ans.rrname)
                mdns.append(rrname)

                # PTR
                if rtype == 12:
                    try:
                        ptr = ans.rdata.decode().rstrip('.')
                    except Exception:
                        ptr = str(ans.rdata)
                    mdns.append(ptr)
                # SRV
                elif rtype == 33:
                    try:
                        srv = ans.target.decode().rstrip('.')
                        port = ans.port
                        mdns.append(f"{srv}:{port}")
                    except Exception:
                        srv = str(ans.target)
                        mdns.append(ans.rdata)
                # TXT
                elif rtype == 16:
                    try:
                        txt = [i.decode() for i in ans.rdata]
                        notes.extend(txt)
                    except Exception as e:
                        print(f"[!] Error parsing TXT answer: {e}")
                # A/AAAA
                elif rtype == 1 or rtype == 28:
                    mdns.append(ans.rdata)

            # Answers
            for i in range(dns.ancount):
                parse_answer(dns.an[i])
                        
            # Authority
            for i in range(dns.nscount):
                parse_answer(dns.ns[i])
            # Additional
            for i in range(dns.arcount):
                parse_answer(dns.ar[i])     
        return mdns, notes
    
    @staticmethod
    def parse_nbns(packet):
        nbns = packet[NBNSHeader]
        names = []
        info = []

        if packet.haslayer(NBNSRegistrationRequest):
            nsbody = packet[NBNSRegistrationRequest]
            if nsbody.QUESTION_NAME and nsbody.QUESTION_NAME.decode() is not None:
                names.extend([nsbody.QUESTION_NAME.decode()])
            elif hasattr(nbns, 'OPCODE') and nbns.OPCODE in [0, 5]:
                if hasattr(nbns, 'RR_NAME') and nbns.RR_NAME:
                    names.extend([nbns.RR_NAME.decode()])

        return names

class Probe:
    """
    Probe object to perform all technical tasks.
    
    Params:
        n_range: a string that is an ip range in cidr notation. (e.g. 192.168.0.0/24)
        iface: a string for the network interface to use with scapy's AsyncSniffer. (e.g. wlan0) Can be left blank.
        aggrlv: an integer that is either 1, 2, or 3, representing the aggression level of the probe, which is determined
            upon initialising an instance and affects what the start() function does.

    """
    def __init__(self, n_range: str, aggrlv: int, iface: str = "Wi-Fi", stream: bool = True):
        self.range = IPv4Network(n_range.strip())
        self.aggrlv = int(aggrlv)
        self.host_list = []
        self.host_list_lock = Lock()
        self.stop_event = Event()
        self.stream = stream
        self.running = False
        self.iface = iface

        # thread pools
        self.packet_processors = ThreadPoolExecutor()
        self.hostlist_updater = ThreadPoolExecutor()

    def toggle_stream(self) -> bool:
        """
        Toggles the stream mode of the Probe object.
        
        Returns:
            bool: The new state of the stream mode.
        """
        self.stream = not self.stream
        return self.stream

    def event_stream_log(self, message: str):
        """
        prints event_stream_log messages to the console.
        
        Args:
            message (str): The message to print.
        """
        if self.stream == True:
            print(message)

    def add_host(self, host: Host):
        """
        Function called to add a Host object to the parent Probe object's host_list.
        Optimized to avoid unnecessary list scans and memory use.
        """
        with self.host_list_lock:
            if not host.ip or not host.mac:
                return
            if host.mac in ["00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"] or host.ip in ["255.255.255.255", "0.0.0.0"]:
                return
            if not IPv4Address(host.ip) in IPv4Network(self.range):
                return

            if not hasattr(self, '_host_index'):
                self._host_index = {}
                for h in self.host_list:
                    self._host_index[h.ip] = h

            host_exists = self._host_index.get(host.ip)

            if host_exists is None:
                self.host_list.append(host)
                self._host_index[host.ip] = host
                self.event_stream_log(f"[+] New host added: {host.ip} {host.mac} {host.hostname} {host.nbns} {host.mdns} {host.ports}")
            else:
                if host_exists.mac != host.mac:
                    host_exists.mac = host.mac
                if host_exists.hostname != host.hostname:
                    host_exists.hostname = host.hostname
                for n in host.nbns:
                    if n not in host_exists.nbns:
                        host_exists.nbns.append(n)
                for m in host.mdns:
                    if m not in host_exists.mdns:
                        host_exists.mdns.append(m)
                for p in host.ports:
                    if p not in host_exists.ports:
                        host_exists.ports.append(p)
                host_exists.last_seen = host.last_seen
            
    def nbns_probe(self):
        NBNS_PORT = 137
        BROADCAST_ADDR = "255.255.255.255"

        req = IP(dst=BROADCAST_ADDR)/UDP(sport=NBNS_PORT, dport=NBNS_PORT)/NBNSHeader()/NBNSNodeStatusRequest()
        while not self.stop_event.is_set():
            send(req, verbose=False)
            print("[nbns_probe] NBNS Probe sent.")
            sleep(rand(self.aggrlv*5, self.aggrlv*10))

    def mdns_probe(self):
        """
        Actively send an mDNS query to discover devices/services on the local network.
        """
        MDNS_ADDR = "224.0.0.251"
        MDNS_PORT = 5353

        query = DNS(rd=1, qd=DNSQR(qname="_services._dns-sd._udp.local", qtype="PTR"))

        packet = IP(dst=MDNS_ADDR)/UDP(dport=MDNS_PORT, sport=MDNS_PORT)/query

        while not self.stop_event.is_set():
            send(packet, verbose=False)
            self.event_stream_log("[mdns_probe] Sent mDNS probe for _services._dns-sd._udp.local")
            sleep(rand(self.aggrlv*5, self.aggrlv *10)) 
            

    def passive_scanner(self):
        """
        Starts an scapy.sendrcv.AsyncSniffer instance to capture and process packets.
        """
        def process_packet(packet: Packet):
            """
            Extracts information from a captured packet to generate Host objects and submit them to add_host.
            """

            sender = Host(None, None, dt.now().time())
            receiver = Host(None, None, dt.now().time())

            if not packet.haslayer(ARP) and not packet.haslayer(IP):
                return
        

            if packet.haslayer(Ether):
                ether = packet[Ether]
                sender.mac = ether.src
                receiver.mac = ether.dst
        

            if packet.haslayer(ARP):
                arp = packet[ARP]
                sender.ip = arp.psrc
                sender.mac = arp.hwsrc
                receiver.ip = arp.pdst
                receiver.mac = arp.hwdst

            if packet.haslayer(IP):
                ip = packet[IP]
                sender.ip = ip.src
                receiver.ip = ip.dst    

            if packet.haslayer(NBNSHeader):
                nbns = Parsers.parse_nbns(packet)
                sender.nbns.extend(nbns)

            if packet.haslayer(DNS) and packet.haslayer(UDP) and (packet[UDP].sport == 5353 or packet[UDP].dport == 5353):
                mdns, info = Parsers.parse_mdns(packet)
                
                sender.mdns.extend(mdns) # the bug happens here, once the mdns is parsed, it is added to the sender's mdns list but after that, every other packet processed will have the same mdns list regardless
                sender.notes.extend(info)

            self.hostlist_updater.submit(self.add_host, sender)

            if IPv4Address(sender.ip) in IPv4Network(self.range):
                self.hostlist_updater.submit(self.add_host, receiver)

            if IPv4Address(receiver.ip) in IPv4Network(self.range):
                self.hostlist_updater.submit(self.add_host, receiver)

        def _submit_process_packet(p):
            self.packet_processors.submit(process_packet, p)
        
        print(f"[+] Starting passive scanner on for range {self.range} at aggression level {self.aggrlv}.")
        sniffer_args = {
            'prn': _submit_process_packet,
            'store': False,
            'promisc': True,
            'filter': f"net ({self.range})"
        }
        if self.iface:
            print(f"[+] Using interface: {self.iface}")
            sniffer_args['iface'] = self.iface
        sniffer = AsyncSniffer(**sniffer_args)
        sniffer.start()

        while not self.stop_event.is_set():
            sniffer.join(1)
        
        print(f"[+] Stopping passive scanner for range {self.range}")
        sniffer.stop()
        print("[+] Sniffer has stopped.")
        


    def aggressive_scan(self):
        #copy code from swordfish
        pass

    def start(self):
        self.stop_event.clear()
        self.running = True

        # Start passive scanner in its own thread
        passive_thread = Thread(target=self.passive_scanner)
        passive_thread.start()

        probe_threads = []
        if self.aggrlv > 1:
            print("[+] Starting mDNS and NBNS probes.")
            mdns_thread = Thread(target=self.mdns_probe)
            nbns_thread = Thread(target=self.nbns_probe)
            mdns_thread.start()
            nbns_thread.start()
            probe_threads.extend([mdns_thread, nbns_thread])

        if self.aggrlv >= 3:
            aggressive_thread = Thread(target=self.aggressive_scan)
            aggressive_thread.start()
            probe_threads.append(aggressive_thread)

        passive_thread.join()
        self.stop_event.set()

        for t in probe_threads:
            t.join()

    def stop(self):
        print("[+] Stop event set.")
        running = False
        self.stop_event.set()
        print("[+] Probe quit successfully.")

    def show(self):
        """
        prints the host list in a formatted manner.
        """
        from scapy.all import get_terminal_width
        print(f"Hosts in range {self.range} ({len(self.host_list)}):")
        print("="*get_terminal_width())
        for host in sorted(self.host_list, key=lambda i: ip_address(i.ip)):
            host.summary(output=True)
        print("="*get_terminal_width())
        print(f"Total hosts: {len(self.host_list)}")

    def search(self, args):
        """
        Searches for hosts based on the provided arguments.
        
        Args:
            args: Parsed arguments from the command line.
        """
        print(f"Searching {len(self.host_list)} hosts in range {self.range} with parameters: {args}")
        found_hosts = []

        for host in self.host_list:
            if args.ip and (host.ip != args.ip):
                continue
            if args.mac and (host.mac != args.mac):
                continue
            if args.names:
                name_matches = False
                for name in args.names.split(','):
                    name = name.strip().lower()
                    for n in host.nbns:
                        n_str = str(n).strip().lower().rstrip('.')
                        
                        if name in n_str:
                            name_matches = True
                            break
                    for m in host.mdns:
                        m_str = str(m).strip().lower().rstrip('.')
                        
                        if name in m_str:
                            name_matches = True
                            break
                    if name_matches:
                        break
                if not name_matches:
                    continue
            if args.ports and not any(port in host.ports for port in map(int, args.ports.split(','))):
                continue

            found_hosts.append(host)

        if found_hosts:
            
            for host in found_hosts:
                host.summary(output=True)
        else:
            print("No matching hosts found.")
