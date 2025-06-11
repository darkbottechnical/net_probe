from scapy.layers.netbios import NBNSHeader, NBNSRegistrationRequest
from scapy.layers.dns import DNS
from ipaddress import IPv6Address
try:
    from modules.databases.service_db import SERVICE_DB
except ModuleNotFoundError:
    from databases.service_db import SERVICE_DB

class Parsers:
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
    def parse_mdns_services(packet):
        dns = packet[DNS]

        mdns_names = []
        services = []
        ports = []
        notes = []
        clean_hostname = None

        if dns.qr == 1:
            def parse_field(ans):
                """Function to extract information from a packet's DNS layer."""
                try:
                    rrname = ans.rrname.decode().rstrip(".") if hasattr(ans, 'rrname') else None
                except Exception:
                    rrname = str(ans.rrname) if hasattr(ans, 'rrname') else None

                if rrname:
                    mdns_names.append(rrname)  # always add rrname to mdns_names list

                rtype = getattr(ans, 'type', None)
                if rtype is None:
                    notes.append("[!] Warning: Missing 'type' attribute in DNS answer.")
                    return

                # if the record is an AAAA record, it won't be a service, so just make note of the ipv6 address
                if rtype == 28:
                    try:
                        v6addr = ans.rdata.decode()
                    except Exception:
                        v6addr = str(IPv6Address(ans.rdata))

                    notes.append(f" IPv6 ADDRESS: {v6addr}")

                # otherwise, it should be a record of a service.
                else:
                    # construct a dict to organise service information (sort of)
                    service = {
                        "name": rrname,
                        "metadata": []
                    }

                    is_known_service = False
                    service_attr_data = None
                    

                    # find whether the service is in the known services database.
                    for name, data in SERVICE_DB.items():
                        if name in rrname:
                            is_known_service: bool = True # if it is, set the boolean to true,
                            service["name"] = data.get("fn") # set the service name to the stored friendly name (fn)
                            service_attr_data = data.get("ca") # and store the known friendly metadata keys.

                    # PTR (Pointer Records)
                    # These just contain a service as rrname and the hostname with the service name as rdata (to be confirmed)
                    if rtype == 12:
                        try:
                            ptr_name = ans.rdata.decode().rstrip(".")
                        except Exception:
                            ptr_name = str(ans.rdata)

                        mdns_names.append(ptr_name)

                    # SRV (Server Records)
                    # These contain a service and its corresponding port number.
                    # This code adds the port to the device's list of open ports and also appends the name in rdata.
                    if rtype == 33:
                        try:
                            srv_name = ans.target.decode().rstrip(".")
                        except Exception:
                            srv_name = str(ans.target)
                        srv_port = ans.port

                        mdns_names.append(srv_name)
                        ports.append(srv_port)
                        service.get("metadata").append(f"Port: {str(srv_port)}") # add port the service is running on to metadata
                    
                    # TXT Records
                    # These are the most complicated ones.
                    # This code parses the key-value metadata pairs and switches the keys to friendly names if known.
                    if rtype == 16:
                        metadata = []

                        try:
                            txt_records = ans.rdata
                            for record in txt_records:
                                if isinstance(record, bytes):
                                    record = record.decode(errors="replace")
                                record = record.strip()
                                if "=" in record:
                                    key, value = record.split("=", 1)
                                    key = key.strip()
                                    value = value.strip()
                                    # Replace key with friendly name if available
                                    if service_attr_data and key in service_attr_data:
                                        key = service_attr_data[key]
                                    metadata.append(f"{key}: {value}")
                                else:
                                    metadata.append(record)
                        except Exception as e:
                            notes.append(f"[!] Error parsing TXT field: {e}")

                        service["metadata"].extend(metadata)
                    services.append(service)
            

            for i in range(dns.ancount):
                if i < len(dns.an):  # Ensure index is within bounds
                    parse_field(dns.an[i])

            for i in range(dns.arcount):
                if i < len(dns.ar):  # Ensure index is within bounds
                    parse_field(dns.ar[i])
        
            for name in mdns_names:
                if name.lower().endswith(".local") and not name.startswith("_"):
                    clean_hostname = name.split(":")[0].split(".", 1)[0]

            
        return mdns_names, services, notes, ports, clean_hostname

    @staticmethod
    def parse_nbns(packet):
        nbns = packet[NBNSHeader]
        names = []
        info = []

        if packet.haslayer(NBNSRegistrationRequest):
            nsbody = packet[NBNSRegistrationRequest]
            if nsbody.QUESTION_NAME is not None:
                try:
                    names.append(nsbody.QUESTION_NAME.decode())
                except UnicodeDecodeError:
                    names.append(str(nsbody.QUESTION_NAME))
            elif hasattr(nbns, 'OPCODE') and nbns.OPCODE in [0, 5]:
                if hasattr(nbns, 'RR_NAME') and nbns.RR_NAME:
                    try:
                        names.append(nbns.RR_NAME.decode())
                    except UnicodeDecodeError:
                        names.append(str(nbns.RR_NAME))

        return names
