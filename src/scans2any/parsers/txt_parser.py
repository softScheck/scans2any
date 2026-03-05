"""
General purpose parser

Parses formatted txt input to gather information.
"""

from collections import defaultdict
from pathlib import Path

from scans2any.helpers.utils import is_valid_ip, match_dns
from scans2any.internal import Host, Infrastructure

CONFIG = {
    "extensions": [".txt"],
}


def add_arguments(parser):
    """
    Add arguments to the parser for input format.
    """
    parser.add_argument(
        "--txt",
        type=str,
        action="append",
        nargs="+",
        metavar="filename/directory",
        help="Plain text formats for addional IP and hostname mapping",
    )


def parse(filename: str | Path) -> Infrastructure:
    """
    Filename should be a plain text file.
    """

    try:
        hosts = __parse_url_ip_format(filename)
    except Exception:
        raise
    infra = Infrastructure(hosts, "Plain text")
    return infra


def __parse_url_ip_format(filename: str | Path) -> list[Host]:
    """
    Parser for plain text lines, formatted like:
    - `example.com 127.0.0.1` (hostname IP)
    - `127.0.0.1 example.com other.example.com` (/etc/hosts style: IP hostname1 hostname2...)
    """

    ips: dict[str, list[str]] = defaultdict(list)
    with open(filename) as file:
        for line in file:
            parts = line.strip().split()
            if len(parts) >= 2:
                # Check if first part is an IP address
                if is_valid_ip(parts[0]):
                    ip = parts[0]
                    # Add all hostnames after the IP
                    for hostname in parts[1:]:
                        if match_dns(hostname):
                            ips[ip].append(hostname.lower())
                # Check if second part is an IP address (original format)
                elif len(parts) == 2 and is_valid_ip(parts[1]):
                    ip = parts[1]
                    hostname = parts[0]
                    if match_dns(hostname):
                        ips[ip].append(hostname.lower())

    # Assemble Host objects
    hosts = []
    for ip, hostnames in ips.items():
        new_host = Host(address=set([ip]), hostnames=set(hostnames), os=set())
        hosts.append(new_host)

    return hosts
