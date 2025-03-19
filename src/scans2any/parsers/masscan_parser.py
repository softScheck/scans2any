"""
Masscan Parser
Parses `JSON` output of masscan.
"""

from typing import TypedDict

from scans2any.helpers.utils import read_json
from scans2any.internal import Host, Infrastructure, Service, SortedSet

CONFIG = {
    "extensions": [".json"],
}


def add_arguments(parser):
    """
    Add arguments to the parser for input format.
    """
    parser.add_argument(
        "--masscan",
        type=str,
        action="append",
        nargs="+",
        metavar="filename/directory",
        help="Masscan JSON port scan files/directory",
    )


def parse(filename: str) -> Infrastructure:
    """
    Parses a Masscan JSON report and returns an Infrastructure object.

    Parameters
    ----------
    filename : str
        Path to the Masscan JSON report file.

    Returns
    -------
    Infrastructure
        Masscan's scan as `Infrastructure` object.
    """
    try:
        masscan_hosts = __parse_json(filename)
    except Exception:
        raise
    infra = Infrastructure(masscan_hosts, "Masscan")
    return infra


def __parse_json(filename: str) -> list[Host]:
    """
    Parses the JSON output of a Masscan report.

    Parameters
    ----------
    filename : str
        Path to the Masscan JSON report file.

    Returns
    -------
    list[Host]
        List of `Host` objects representing the parsed data.
    """

    hosts: list[Host] = []

    class PortInfo(TypedDict):
        port: int
        proto: str

    class ScanObject(TypedDict):
        ip: str
        ports: list[PortInfo]

    scan_data: list[ScanObject] = read_json(filename, list)

    for obj in scan_data:
        try:
            new_host = Host(address=obj["ip"], hostnames=SortedSet(), os=SortedSet())
            service = obj["ports"][0]
            new_service = Service(
                port=service["port"],
                protocol=service["proto"],
                service_names=SortedSet(),
                banners=SortedSet(),
            )
            new_host.add_service(new_service)
            hosts.append(new_host)
        except (KeyError, IndexError):
            continue  # Skip incomplete objects from partial parsing

    return hosts
