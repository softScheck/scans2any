"""
Nmap Parser

Nmap Parser based on [python-libnmap](https://libnmap.readthedocs.io/en/latest/objects.html)
"""

from pathlib import Path

from libnmap.objects.os import NmapOSMatch
from libnmap.parser import NmapHost, NmapParser, NmapParserException

from scans2any.helpers.utils import find_os, match_fqdn
from scans2any.internal import Host, Infrastructure, Service, SortedSet

CONFIG = {
    "extensions": [".xml"],
}


def add_arguments(parser):
    """
    Add arguments to the parser for input format.
    """
    parser.add_argument(
        "--nmap",
        type=str,
        action="append",
        nargs="+",
        metavar="filename/directory",
        help="XML nmap scan files/directory",
    )


def parse(filename: str | Path) -> Infrastructure:
    """
    Parses Nmap XML report.

    Parameters
    ----------
    filename : str | Path
        Path to XML Nmap report

    Returns
    -------
    Infrastructure
        Nmap's scan as `Infrastructure` object.
    """

    try:
        nmap_report = NmapParser.parse_fromfile(str(filename))
    except NmapParserException:
        # Try to parse incomplete aborted Nmap scan
        try:
            nmap_report = NmapParser.parse_fromfile(filename, incomplete=True)
        except NmapParserException:
            raise

    infra = Infrastructure(identifier="Nmap")
    new_hosts = []

    for nmap_host in nmap_report.hosts:
        nmap_os: set[tuple[str, str]] = set(
            (osvalue, infra.identifier) for osvalue in __detect_os(nmap_host)
        )

        lower_hostnames: set[str] = set(
            hostname.lower() for hostname in nmap_host.hostnames
        )

        # Identify more hostnames from script results
        for script in nmap_host.scripts_results:
            fqdn = script.get("elements", {}).get("fqdn")
            if fqdn:
                lower_hostnames.add(fqdn.lower())

        # Iterate over services to extract more details
        for nservice in nmap_host.services:
            for script in nservice.scripts_results:
                elements = script.get("elements", {})

                # Extract and add DNS_Computer_Name if available
                dns_computer_name = elements.get("DNS_Computer_Name")
                if dns_computer_name:
                    lower_hostnames.add(dns_computer_name.lower())

                # Extract and process certificate subjects
                subject = elements.get("subject", {})
                common_name = subject.get("commonName")
                if common_name and match_fqdn(common_name):
                    lower_hostnames.add(common_name.lower())

            # Extract os type from banner
            ostype = nservice.banner_dict.get("ostype", {})
            if ostype:
                os_name = find_os(ostype)
                if os_name:
                    nmap_os.add((os_name, infra.identifier))
            hostname = nservice.banner_dict.get("hostname", {})
            # Extract hostname from banner, strip leading/trailing whitespaces
            if hostname:
                lower_hostnames.add(hostname.lower().strip(" "))

        new_host = Host(
            address=set([nmap_host.address]), hostnames=lower_hostnames, os=nmap_os
        )

        new_services = []
        for nmap_service in nmap_host.services:
            # With UDP-Scans nmap sets the state to "open|filtered" if no answer
            # was received.
            if nmap_service.protocol == "udp" and nmap_service.state != "open":
                continue
            new_service = Service(
                port=nmap_service.port,
                protocol=nmap_service.protocol,
                service_names=SortedSet([nmap_service.service.lower()]),
                banners=SortedSet([nmap_service.banner])
                if nmap_service.banner
                else SortedSet(),
            )
            new_services.append(new_service)
        new_host.add_services(new_services)

        new_hosts.append(new_host)

    infra.add_hosts(new_hosts)
    return infra


def __detect_os(nmap_host: NmapHost) -> list[str]:
    """
    Detect os from nmaps <osmatch>'es.

    `all_matches`: incorporate all possible matches (with `min_accuracy`)

    Returns
    -------
    list[str]
        List of detected os's
    """

    detected_os = []
    os_matches = nmap_host.os_match_probabilities()

    # Highest accuracy --> lowest accuracy
    os_matches.sort(key=lambda m: m.accuracy, reverse=True)

    # Execute detection strategy
    detected_os = __detect_os_all_matches(os_matches)

    return detected_os


def __detect_os_all_matches(os_matches: list[NmapOSMatch]) -> list[str]:
    """
    Detect Nmap os's using `all_matches` strategy.

    Parameters
    ----------
    os_matches : list[NmapOSMatch]
        Sorted list (descending) of possible os matches.

    Returns
    -------
    list[str]
        All matches, mapped to their os string (see utils.find_os)
    """

    detected_os = set()

    for os_match in os_matches:
        # min accuracy
        if os_match.accuracy < 92:
            break
        # save os map
        os = find_os(os_match.name)
        if os:
            detected_os.add(os)

    return list(detected_os)
