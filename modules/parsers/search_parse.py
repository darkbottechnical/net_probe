from argparse import ArgumentParser

def get_parser():
    """
    Returns the ArgumentParser object for the Necronomicon Network Probe.

    This parser is used to handle command-line arguments for filtering packets and hosts.
    It includes options for specifying IP ranges, individual IP addresses, MAC addresses,
    hostnames, and ports.

    Returns:
        ArgumentParser: Configured ArgumentParser object.
    """
    search_parser = ArgumentParser(description="Necronomicon Network Probe")
    search_parser.add_argument(
        "-r", "--range",
        type=str,
        required=False,
        metavar="CIDR",
        help="IP range in CIDR notation to filter packets and hosts. Defaults to the local network CIDR if not specified."
    )
    search_parser.add_argument(
        "-i", "--ip",
        type=str,
        required=False,
        metavar="IP",
        help="IP address to filter packets and hosts."
    )
    search_parser.add_argument(
        "-m", "--mac",
        type=str,
        required=False,
        metavar="MAC",
        help="MAC address to filter packets and hosts."
    )
    search_parser.add_argument(
        "-n", "--names",
        type=str,
        required=False,
        metavar="NAME",
        help="Hostnames, nbns and mdns names to filter packets and hosts."
    )
    search_parser.add_argument(
        "-p", "--ports",
        type=str,
        required=False,
        metavar="PORTS",
        help="Ports to filter packets and hosts."
    )
    search_parser.add_argument(
        "-e", "--extra-notes",
        type=str,
        required=False,
        metavar="NOTES",
        help="Extra notes to filter packets and hosts."
    )
    return search_parser