"""Parse scans2any's own JSON export format back into an Infrastructure."""

import json
import re
from pathlib import Path

from scans2any.helpers.utils import is_valid_ip, read_json
from scans2any.internal import Host, Infrastructure, Service, SortedSet

# None signals that the JSON parser accepts arbitrary custom column names
# because it reads key/value pairs from the file dynamically.
CUSTOM_COLUMNS: dict[str, str] | None = None

CONFIG = {
    "extensions": [".json"],
}


def add_arguments(parser):
    """
    Add arguments to the parser for input format.
    """
    parser.add_argument(
        "--json",
        type=str,
        action="append",
        nargs="+",
        metavar="filename/directory",
        help="JSON files/directory",
    )


# This parser turns a json into an infrastructure, for more information on the
# structure of the json, please see the json writer at
# src/scans2any/writers/json_writer.py.
def parse(filename: str | Path) -> Infrastructure:
    """
    Parses JSON infrastructure.

    Parameters
    ----------
    filename : str | Path
        Path to JSON output file.

    Returns
    -------
    Infrastructure
        Scan as `Infrastructure` object.
    """
    try:
        content = read_json(filename, dict)
        json_hosts = __parse_json(content)
    except Exception:
        raise
    return Infrastructure(json_hosts, "JSON")


def parse_string(content: str) -> Infrastructure:
    infra = json.loads(content)
    json_hosts = __parse_json(infra)
    return Infrastructure(json_hosts, "JSON")


def __parse_json(infra: dict) -> list[Host]:
    hosts = []
    for ip in infra:
        os_origin_construct = []
        for os in infra[ip].get("os", []):
            os_origin_construct.append((os, "json"))

        # Build a list of valid ip addresses from the key and from
        # "ip-addresses".
        addresses = []
        for entry in [ip, *(infra[ip].get("ip-addresses") or [])]:
            if re.match(pattern="^unknown_.*$", string=entry):
                continue
            elif is_valid_ip(entry):
                addresses.append(entry)
            else:
                # The address is neither unknown nor valid.
                # To avoid accepting invalid hosts, we discard the entire host.
                raise

        custom_fields = {}
        for key, value in infra[ip].items():
            if key not in (
                "ip-addresses",
                "hostnames",
                "os",
                "tcp_ports",
                "udp_ports",
                "tcp_status",
                "udp_status",
            ):
                custom_fields[key] = (
                    set(value) if isinstance(value, list) else set([value])
                )

        host = Host(
            address=set(addresses),
            hostnames=SortedSet(infra[ip].get("hostnames", [])),
            os=SortedSet(os_origin_construct),
            custom_fields=custom_fields,
        )
        services = []
        for port in infra[ip].get("tcp_ports", []):
            services.append(
                __new_service(
                    infra[ip]["tcp_ports"],
                    port,
                    "tcp",
                )
            )
        for port in infra[ip].get("udp_ports", []):
            services.append(
                __new_service(
                    infra[ip]["udp_ports"],
                    port,
                    "udp",
                )
            )
        host.add_services(
            new_services=services,
        )
        hosts.append(host)

    return hosts


def __new_service(port_dict: dict, port: str, protocol: str) -> Service:
    custom_fields = {}
    for key, value in port_dict[port].items():
        if key not in ("service_names", "banners"):
            custom_fields[key] = set(value) if isinstance(value, list) else set([value])

    service = Service(
        port=int(port),
        protocol=protocol,
        service_names=SortedSet(
            port_dict[port].get("service_names", []),
        ),
        banners=SortedSet(
            port_dict[port].get("banners", []),
        ),
        custom_fields=custom_fields,
    )
    return service
