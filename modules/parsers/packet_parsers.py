from scapy.layers.netbios import NBNSHeader, NBNSRegistrationRequest
from scapy.layers.dns import DNS
from ipaddress import IPv6Address


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
