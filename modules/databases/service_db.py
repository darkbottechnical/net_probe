SERVICE_DB = {
    "_airplay": {
        "fn": "Apple Airplay",
        "oss": [],
        "ca": {
            "srcvers": "Version",
            "deviceid": "MAC Address",
            "model": "Device Model",
            "features": "Features",
            "protovers": "Protocol Version",
        },
        "doc": "https://openairplay.github.io/airplay-spec/service_discovery.html"
    },
    "_raop":  {
        "fn": "Apple Remote Audio Output Protocol",
        "oss": [],
        "ca": {
            "vs": "Version",
            "am": "Device Model",
            "ft": "Supported Features",
            "tp": "Transportation Protocol",
            "cn": "Supported Codec Numbers",
            "da": "Device Authentication Required",
            "pk": "Public Key",
            "et": "Encryption Types",
            "sf": "Status Flags",
            "md": "Model Numbers",
            "vn": "Version Number",
            "vv": "Volume Version"
        },
        "doc": "https://openairplay.github.io/airplay-spec/service_discovery.html#_raop_tcp"
    },
    "_companion-link": {
        "fn": "Apple Companion Link",
        "oss": [],
        "ca": {
            "rpHA": "HomeKit AuthTag",
            "rpHN": "Discovery Nonce",
            "rpVr": "Protocol Version",
            "rpMac": "Device Model Name",
            "rpFl": "Status Flags",
            "rpAD": "Bonjour Auth Tag",
            "rpHI": "HomeKit Rotating ID",
            "rpBA": "Bluetooth Address"
        }
    },
    "_spotify-connect": {
        "fn": "Spotify Connect",
        "oss": [],
        "ca": {
            "cpath": "ZeroConf Path",
        },
        "doc": "https://developer.spotify.com/documentation/commercial-hardware/implementation/guides/zeroconf"
    },
    "_dosvc": {
        "fn": "Windows Delivery Optimisation Service",
        "oss": [],
        "ca": {
            "sh*": "Service Hash",
        }
    },
    "_googlecast": {
        "fn": "Google Chromecast",
        "oss": [],
        "ca": {
            "id": "Device ID",
            "md": "Device Model",
            "ve": "Software Version",
            "ic": "Icon URL",
            "fn": "Friendly Name",
            "ca": "Certification Authority",
            "fn": "Friendly Name",
            "st": "Status",
            "rs": "Receiver Status",
        },
        "doc": "https://oakbits.com/google-cast-protocol-discovery-and-connection.html"
    },
    "_ipp": {
        "fn": "Internet Printer",
        "oss": [],
        "ca": {
            "ty": "Printer Type",
            "model": "Printer Model",
            "adminurl": "Admin URL",
            "uuid": "Unique Identifier",
            "product": "Product Name",
            "ver": "Version",
            "srcvers": "Source Version",
            "pdl": "Supported Page Description Languages",
            "note": "Notes"
        }
    },
    "_ippusb": {
        "fn": "USB Printer (IPP over USB)",
        "oss": [],
        "ca": {
            "ty": "Printer Type",
            "model": "Printer Model",
            "adminurl": "Admin URL",
            "uuid": "Unique Identifier",
            "product": "Product Name",
            "ver": "Version",
            "srcvers": "Source Version",
            "pdl": "Supported Page Description Languages",
            "note": "Notes"
        }
    },
    "_homekit": {
        "fn": "Apple Homekit",
        "oss": [],
        "ca": {
            
        }
    },
    "_ssh": {
        "fn": "Secure Shell Server",
        "oss": [],
        "ca": {
            
        }
    },
    "_smb": {
        "fn": "Windows File Sharing (Server Message Block)",
        "oss": [],
        "ca": {
            
        }
    },
    "_afpovertcp": {
        "fn": "Apple File Sharing over TCP",
        "oss": [],
        "ca": {
            
        }
    },
    "_workstation": {
        "fn": "Workstation Prescence",
        "oss": [],
        "ca": {
            
        }
    },
    "_http": {
        "fn": "Hypertext Transfer Protocol",
        "oss": [],
        "ca": {
            
        }
    },
    "_ftp": {
        "fn": "File Transfer Protocol",
        "oss": [],
        "ca": {
            
        }
    },
    "_hap": {
        "fn": "HomeKit Accessory Protocol",
        "oss": [],
        "ca": {
            
        }
    },
    "_services._dns-sd": {
        "fn": "mDNS Service Discovery",
        "oss": [],
        "ca": {
        }
    },
    "in-addr.arpa": {
        "fn": "Internet Protocol Version 4"
    },
    "ip6.arpa": {
        "fn": "Internet Protocol Version 6",
        "oss": [],
        "ca": {}
    }    

}