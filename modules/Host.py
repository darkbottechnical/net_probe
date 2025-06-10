from modules.databases.oui_dict import OUI_DICT

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