"""
Bloodhound parser
Extracts information (Hostname & OS) from Bloodhound JSON files.
Does not extract any services, ports or IP-Adresses!
"""

from pathlib import Path

from scans2any.helpers.utils import find_os, read_json
from scans2any.internal import Host, Infrastructure

CONFIG = {
    "extensions": [".json"],
}


def add_arguments(parser):
    """
    Add arguments to the parser for input format.
    """
    parser.add_argument(
        "--bloodhound",
        type=str,
        action="append",
        nargs="+",
        metavar="filename/directory",
        help="Bloodhound computer JSON file/directory",
    )


def parse(filename: str | Path) -> Infrastructure:
    """
    Parses Bloodhound JSON Computers report.

    Parameters
    ----------
    filename : str | Path
        Path to JSON Bloodhound report

    Returns
    -------
    Infrastructure
        Bloodhound's scan as `Infrastructure` object.
    """

    try:
        # Bloodhound is trusted for hostnames and OS
        infra = Infrastructure(
            __parse_json(filename),
            identifier="Bloodhound",
            trusted_fields={"host": ["hostname", "os"]},
        )
    except Exception:
        raise
    return infra


def __parse_json(filename: str | Path) -> list[Host]:
    hosts: list[Host] = []
    data: dict[str, dict] = read_json(filename, dict)

    for host in data.get("data", []):
        try:
            hostos: set[tuple[str, str]] = set()
            properties = host.get("Properties", {})
            name = properties.get("name")
            operatingsystem = properties.get("operatingsystem")
            os_result = find_os(operatingsystem) if operatingsystem else None

            if os_result:
                hostos.add((os_result, "Bloodhound"))

            hosts.append(
                Host(
                    address=set(),
                    hostnames=set([name.lower()]),
                    os=hostos,
                    trusted_fields={
                        "hostname",
                        "os",
                    },  # Bloodhound is accurate on these
                )
            )
        except (KeyError, IndexError):
            continue  # Skip incomplete objects from partial parsing
    return hosts
