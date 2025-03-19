"""Prints a XML representation of the infrastructure."""

import xml.dom.minidom
from xml.etree import ElementTree as ET

from scans2any.internal import Infrastructure, printer
from scans2any.writers.dataframe_creator import create_data_unmerged

NAME = "xml"
PROPERTIES = {
    "binary": False,
    "ignore-conflicts": False,
}


def add_elements(
    parent: ET.Element, container_tag: str, children: list[str] | None, element_tag: str
) -> None:
    """
    Helper to add a container with child elements to the parent element.
    """
    if children:
        container = ET.SubElement(parent, container_tag)
        for child in children:
            if child:
                elem = ET.SubElement(container, element_tag)
                elem.text = child


def add_ports(parent: ET.Element, container_tag: str, ports: dict | None) -> None:
    """
    Helper to add port information (TCP or UDP) to the parent element.
    """
    if ports:
        container = ET.SubElement(parent, container_tag)
        for port_num, port_data in ports.items():
            port_elem = ET.SubElement(
                container, "port", attrib={"number": str(port_num)}
            )
            add_elements(
                port_elem, "services", port_data.get("service_names"), "service"
            )
            add_elements(port_elem, "banners", port_data.get("banners"), "banner")


def write(infra: Infrastructure, args) -> str:
    """
    Convert the internal representation of the infrastructure
    into the XML format.
    """
    infra.sort()
    infra.cleanup_names("\"'<>&")

    data_dict = create_data_unmerged(infra, columns=args.columns)

    root = ET.Element("infrastructure")

    for ip, host_data in data_dict.items():
        host_elem = ET.SubElement(root, "host", attrib={"ip": ip})

        add_elements(host_elem, "hostnames", host_data.get("hostnames"), "hostname")
        add_elements(host_elem, "os_info", host_data.get("os"), "os")

        add_ports(host_elem, "tcp_ports", host_data.get("tcp_ports"))
        add_ports(host_elem, "udp_ports", host_data.get("udp_ports"))

    xml_string = ET.tostring(root, encoding="unicode")
    dom = xml.dom.minidom.parseString(xml_string)
    pretty_xml = dom.toprettyxml(indent="  ")

    printer.success(
        f"XML with {len(pretty_xml.splitlines())} lines has been created from parsed input data"
    )
    return pretty_xml
