from ipaddress import (
    IPv4Address, 
    IPv6Address,
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

from modules.oui_dict import OUI_DICT

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

    Attributes after initialization:
        vendor: string object representing the vendor of the host, defaults to "N/A".
        notes: list of strings for any extra notes about the host, defaults to an empty list.
        packet_count: integer representing the number of packets seen from this host, defaults to 0.

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
        self.packet_count = 0

    @property
    def vendor(self):
        if self.mac:
            import re
            mac_clean = re.sub(r'[^0-9A-Fa-f]', '', self.mac).upper()
            if len(mac_clean) >= 6:
                oui = mac_clean[:6]
                return OUI_DICT.get(oui, "N/A")
        return "N/A"

    def info(self, output: bool=False):
        info = f"""
HOST INFORMATION FOR {self.ip}
  IPV4 ADDRESS: {self.ip}
  MAC 
    ADDRESS:  {self.mac}
    VENDOR:      {self.vendor}
  HOSTNAME:     {self.hostname}
  NBNS NAMES:   {', '.join(self.nbns)}
  MDNS NAMES:   {', '.join(self.mdns)}
  OPEN PORTS:   {', '.join(str(p) for p in self.ports)}
  LAST SEEN:    {self.last_seen}
  PACKET COUNT: {self.packet_count}

EXTRA NOTES AND INFO:
  {"\n".join(self.notes)}

"""
        if output:
            print(info)
        else:
            return info

    def summary(self, output: bool=False, col_widths=None):
        """
        Returns a summary of the host's information with aligned columns.
        If col_widths is provided, uses those widths for each column.
        """
        fields = [
            self.ip or '',
            self.mac or '',
            self.vendor or '',
            str(self.last_seen) or '',
            str(self.hostname) or '',
            str(len(self.nbns)),
            str(len(self.mdns)),
            ', '.join(str(p) for p in self.ports)
        ]
        if col_widths:
            # Truncate fields that are too long for their column
            display_fields = []
            for i, field in enumerate(fields):
                if len(field) > col_widths[i] - 1:
                    display_fields.append(field[:col_widths[i]-4] + '...')
                else:
                    display_fields.append(field)
            summary = ''.join(f"{display_fields[i]:<{col_widths[i]}}" for i in range(len(fields)))
        else:
            summary = (
                f"{self.ip:<15} "
                f"{self.mac:<20} "
                f"{self.vendor:<30} "
                f"{str(self.last_seen):<18} "
                f"{str(self.hostname):<30} "
                f"NBNS:{len(self.nbns):<5} "
                f"MDNS:{len(self.mdns):<5} "
                f"PORTS:{', '.join(str(p) for p in self.ports)}"
            )
        if output:
            print(summary)
        else:
            return summary

class Parsers:

    COMMON_SERVICES = {
        "_airplay._tcp.local": "Apple AirPlay",
        "_raop._tcp.local": "AirPlay Audio (RAOP)",
        "_spotify-connect._tcp.local": "Spotify Connect",
        "_dosvc._tcp.local": "Windows Delivery Optimization Service (DOSVC)",
        "_googlecast._tcp.local": "Google Cast (Chromecast)",
        "_ipp._tcp.local": "Internet Printer (IPP)",
        "_ippusb._tcp.local": "USB Printer (IPP over USB)",
        "_homekit._tcp.local": "Apple HomeKit Accessory",
        "_ssh._tcp.local": "SSH Service",
        "_smb._tcp.local": "Windows File Sharing (SMB)",
        "_afpovertcp._tcp.local": "Apple File Sharing (AFP)",
        "_workstation._tcp.local": "Workstation Presence",
        "_http._tcp.local": "HTTP Web Server",
        "_ftp._tcp.local": "FTP File Transfer",
        "_hap._tcp.local": "HomeKit Accessory Protocol",
        "_services._dns-sd._udp.local": "mDNS Service Discovery",
    }

    @staticmethod
    def parse_arp_cache():
        import subprocess
        import platform

        os = platform.system().lower()

        if os == "windows":
            arp_cache = subprocess.run(["arp", "-a"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).stdout
            pairs = [pair.split() for pair in arp_cache.split('\n')]

            for pair in pairs:
                if len(pair) == 3:
                    return pair[0], pair[1]

        elif os == "linux":
            arp_cache = subprocess.run(["arp"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).stdout
            rows = [row.split() for row in arp_cache.split('\n')]

            for row in rows:
                if len(row) == 5:
                    return row[0], row[2]
        else:
            print("Sorry, your platform isn't supported by this script. Please notify the author if you want it to be because he is lazy.")

    @staticmethod
    def parse_mdns(packet):
        dns = packet[DNS]
        mdns = []
        notes = []
        ports = []
        matched_services = set()
        clean_hostname = None

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
                        ports.append(port)
                    except Exception:
                        port = ans.port
                        srv = str(ans.target)
                        mdns.append(f"{srv}:{port}")
                        ports.append(port)
                # TXT
                elif rtype == 16:
                    try:
                        txt_pairs = []
                        highlights = []
                        for i in ans.rdata:
                            if isinstance(i, bytes):
                                i = i.decode(errors="replace")
                            i = i.strip()
                            if '=' in i:
                                k, v = i.split('=', 1)
                                k = k.strip().lower()
                                v = v.strip()
                                txt_pairs.append(f"    {k}: {v}")
                                # Highlight common fields
                                if k in ("model", "id", "deviceid", "fn", "product", "ty", "uuid", "md", "ver", "srcvers", "adminurl", "srvvers"):
                                    highlights.append(f"      [*] {k}: {v}")
                            else:
                                txt_pairs.append(f"    {i}")
                        if highlights:
                            notes.append(f"  HIGHLIGHTS FOR {ans.rrname}:\n" + "\n".join(highlights))
                        if txt_pairs:
                            notes.append(f"  MDNS TXT RECORD FOR {ans.rrname}:\n" + "\n".join(txt_pairs))
                    except Exception as e:
                        print(f"[!] Error parsing TXT answer: {e}")
                # AAAA
                elif rtype == 28:
                    try:
                        ipv6 = "    IPv6 Address: "+ans.rdata.decode()
                    except Exception:
                        ipv6 = "    IPv6 Address: "+str(IPv6Address(ans.rdata))
                    notes.append(ipv6)

            # Answers
            for i in range(dns.ancount):
                parse_answer(dns.an[i])
            # Authority
            for i in range(dns.nscount):
                parse_answer(dns.ns[i])
            # Additional
            for i in range(dns.arcount):
                parse_answer(dns.ar[i])

            for service in mdns:
                service_lc = service.lower()
                for key, label in Parsers.COMMON_SERVICES.items():
                    if key in service_lc and key not in matched_services:
                        notes.append(f"    Service Running: {label} ({key})")
                        matched_services.add(key)

            # Extract clean hostname
            for name in mdns:
                if name.lower().endswith('.local') and not name.startswith('_'):
                    is_service = False
                    for key in Parsers.COMMON_SERVICES:
                        if name.lower() == key:
                            is_service = True
                            break
                    if not is_service:
                        clean_hostname = name.split(':')[0].split('.', 1)[0]
                        break

        return mdns, notes, ports, clean_hostname
    
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

    Attributes after initialization:
        range: an IPv4Network object representing the network range.
        aggrlv: an integer representing the aggression level.
        host_list: a list of Host objects representing the hosts found in the network.
        host_list_lock: a threading.Lock object to manage access to host_list.
        stop_event: a threading.Event object to signal when to stop scanning.
        stream: a boolean indicating whether to print event logs to the console.
        running: a boolean indicating whether the probe is currently running.
        iface: a string representing the network interface to use for packet sniffing.

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
                if host_exists.hostname != host.hostname and host.hostname != "N/A":
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
                for note in host.notes:
                    if note not in host_exists.notes:
                        host_exists.notes.append(note)
                host_exists.last_seen = host.last_seen
            
    def nbns_probe(self):
        NBNS_PORT = 137
        BROADCAST_ADDR = "255.255.255.255"

        req = IP(dst=BROADCAST_ADDR)/UDP(sport=NBNS_PORT, dport=NBNS_PORT)/NBNSHeader()/NBNSNodeStatusRequest()
        while not self.stop_event.is_set():
            if self.iface:
                send(req, verbose=False, iface=self.iface)
            else:
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
            if self.iface:
                send(packet, verbose=False, iface=self.iface)
            else:
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
                mdns, info, ports, clean_hostname = Parsers.parse_mdns(packet)
                sender.mdns.extend(mdns)
                sender.notes.extend(info)
                sender.ports.extend(ports)

                # Update hostname only if clean_hostname is valid and sender.hostname is empty or "N/A"
                if clean_hostname and (not sender.hostname or sender.hostname == "N/A"):
                    sender.hostname = clean_hostname

            if IPv4Address(sender.ip) in IPv4Network(self.range):
                self.add_host(sender)
                # Increment packet count for sender
                if hasattr(self, '_host_index') and sender.ip in self._host_index:
                    self._host_index[sender.ip].packet_count += 1

            if IPv4Address(receiver.ip) in IPv4Network(self.range):
                self.add_host(receiver)
                # Increment packet count for receiver
                if hasattr(self, '_host_index') and receiver.ip in self._host_index:
                    self._host_index[receiver.ip].packet_count += 1

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
        # coming eventually
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
        Prints the host list in a dynamically formatted table based on content width.
        Truncates columns if content is too wide for the terminal.
        """
        from scapy.all import get_terminal_width
        headers = [
            ("IP Address", lambda h: h.ip or ""),
            ("MAC Address", lambda h: h.mac or ""),
            ("MAC Vendor", lambda h: h.vendor or ""),
            ("Last Seen", lambda h: str(h.last_seen) or ""),
            ("Hostname", lambda h: str(h.hostname) or ""),
            ("NBNS", lambda h: str(len(h.nbns))),
            ("MDNS", lambda h: str(len(h.mdns))),
            ("PORTS", lambda h: ', '.join(str(p) for p in h.ports)),
        ]
        # Calculate max width for each column
        col_widths = []
        for idx, (header, getter) in enumerate(headers):
            max_content = max([len(getter(h)) for h in self.host_list] + [len(header)])
            col_widths.append(max_content + 2)
        # Adjust total width to fit terminal
        term_width = get_terminal_width()
        total_width = sum(col_widths)
        if total_width > term_width:
            # Proportionally shrink columns, but keep a minimum width
            min_widths = [8, 10, 10, 10, 10, 5, 5, 8]
            excess = total_width - term_width
            for i in range(len(col_widths)):
                reducible = col_widths[i] - min_widths[i]
                if reducible > 0 and excess > 0:
                    reduction = min(reducible, excess)
                    col_widths[i] -= reduction
                    excess -= reduction
                if excess <= 0:
                    break
        # Print header
        header_line = ''.join(f"{header:<{col_widths[i]}}" for i, (header, _) in enumerate(headers))
        print(header_line)
        print("=" * min(term_width, sum(col_widths)))
        # Print each host
        for host in sorted(self.host_list, key=lambda i: ip_address(i.ip)):
            host.summary(output=True, col_widths=col_widths)
        print("=" * min(term_width, sum(col_widths)))
        print(f"Total hosts: {len(self.host_list)}")

    def search(self, args):
        """
        Searches for hosts based on the provided arguments.
        
        Args:
            args: Parsed arguments from the command line.
        """
        from scapy.all import get_terminal_width
        self.event_stream_log(f"[+] Searching {len(self.host_list)} hosts in range {self.range} with parameters: {args}")
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

                    if name == host.hostname:
                        name_matches = True
                        break
                    
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
            if args.extra_notes:
                notes_matches = False
                for note in args.extra_notes.split(','):
                    note = note.strip().lower()
                    if any(note in n.lower() for n in host.notes):
                        notes_matches = True
                        break
                if not notes_matches:
                    continue

            found_hosts.append(host)

        if found_hosts:
            print(f"Found {len(found_hosts)} matching hosts:")

            headers = [
                ("IP Address", lambda h: h.ip or ""),
                ("MAC Address", lambda h: h.mac or ""),
                ("MAC Vendor", lambda h: h.vendor or ""),
                ("Last Seen", lambda h: str(h.last_seen) or ""),
                ("Hostname", lambda h: str(h.hostname) or ""),
                ("NBNS", lambda h: str(len(h.nbns))),
                ("MDNS", lambda h: str(len(h.mdns))),
                ("PORTS", lambda h: ', '.join(str(p) for p in h.ports)),
            ]

            # Calculate max width for each column
            col_widths = []
            for idx, (header, getter) in enumerate(headers):
                max_content = max([len(getter(h)) for h in found_hosts] + [len(header)])
                col_widths.append(max_content + 2)

            # Adjust total width to fit terminal
            term_width = get_terminal_width()
            total_width = sum(col_widths)
            if total_width > term_width:
                # Proportionally shrink columns, but keep a minimum width
                min_widths = [8, 10, 10, 10, 10, 5, 5, 8]
                excess = total_width - term_width
                for i in range(len(col_widths)):
                    reducible = col_widths[i] - min_widths[i]
                    if reducible > 0 and excess > 0:
                        reduction = min(reducible, excess)
                        col_widths[i] -= reduction
                        excess -= reduction
                    if excess <= 0:
                        break

            # Print header
            header_line = ''.join(f"{header:<{col_widths[i]}}" for i, (header, _) in enumerate(headers))
            print(header_line)
            print("=" * min(term_width, sum(col_widths)))

            # Print each host
            for host in found_hosts:
                host.summary(output=True, col_widths=col_widths)

            print("=" * min(term_width, sum(col_widths)))
        else:
            print("No matching hosts found.")
