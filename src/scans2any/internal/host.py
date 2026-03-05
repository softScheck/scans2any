"""Host data model representing a single network host and its services."""

import textwrap
from typing import Any, Self  # Use class type inside of the same class

from pydantic import BaseModel, ConfigDict, Field, model_validator

from scans2any.internal import printer
from scans2any.internal.service import OverridingNoConflictError, Service
from scans2any.internal.sorted_set import SortedSet


class HostIntegrationError(Exception):
    pass


class Host(BaseModel):
    """
    Internal representation of an IPv4 host and corresponding information.

    Attributes
    ----------
    address : set[str] | SortedSet[str]
        IP Addresses
    hostnames : set[str] | SortedSet[str]
        List of corresponding hostnames
    services : list[Service]
        A list of available services
    os : set[tuple] | SortedSet[str]
        Operating system, if available

    Methods
    -------
    add_service(self, port: str, protocol: str, service: str, banner: str)
        Adds a new service to the host
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    address: set[str] | SortedSet[str]
    hostnames: set[str] | SortedSet[str]
    os: set[tuple[str, str]] | SortedSet[str]
    services: list[Service] = Field(default_factory=list)
    trusted_fields: set[str] = Field(default_factory=set)
    custom_fields: dict[str, set] = Field(default_factory=dict)

    @model_validator(mode="after")
    def check_address_or_hostname(self) -> Self:
        if not self.address and not self.hostnames:
            raise ValueError(
                "A host must always have at least one of address or hostname"
            )
        return self

    def add_service(self, new_service: Service, *, prioritize_self: bool = False):
        """
        Adds the service object to the list of services.

        Makes sure that there are no duplicate services, by combining services
        with the same port immediately.

        Optionally, we can use this host as priority, to to avoid collisions, i.
        e. multiple service names and/or banners.

        Parameters
        ----------
        service : Service
            Service type object to be added to the list of services
        prioritize_self: bool
            Call `merge_with_service` instead of `union_with_service` on
            service, if it has to be integrated into an existing service of
            `self`.
        """

        for service in self.services:
            if (
                service.port == new_service.port
                and service.protocol == new_service.protocol
            ):
                try:
                    if prioritize_self:
                        service.merge_with_service(new_service)
                    else:
                        service.union_with_service(new_service)
                    return
                except OverridingNoConflictError as e:
                    e.print_warning(self.identifier())
                    return

        # No service with the new services port yet
        self.services.append(new_service)

    def add_services(
        self, new_services: list[Service], *, prioritize_self: bool = False
    ):
        """
        Adds multiple services to the host.

        Parameters
        ----------
        new_services : list[Service]
            Service objects to be added to the list of services
        prioritize_self: bool
            Passed to calls of `self.add_service()`
        """

        service_map = {(s.port, s.protocol): s for s in self.services}

        for new_service in new_services:
            key = (new_service.port, new_service.protocol)
            if key in service_map:
                service = service_map[key]
                try:
                    if prioritize_self:
                        service.merge_with_service(new_service)
                    else:
                        service.union_with_service(new_service)
                except OverridingNoConflictError as e:
                    e.print_warning(self.identifier())
            else:
                self.services.append(new_service)
                service_map[key] = new_service

    def remove_service(self, port: int):
        """
        Removes service with the specified port from the host.
        """

        self.services = [service for service in self.services if service.port != port]

    def remove_services(self, ports: tuple[int, int]):
        """
        Removes services with ports in the specified port-range from the host.
        """

        port_range = set(range(ports[0], ports[1] + 1))
        self.services = [
            service for service in self.services if service.port not in port_range
        ]

    def get_service_by_port(self, port: int):
        """
        Returns the service corresponding to the specified port or None.
        """

        for service in self.services:
            if service.port == port:
                return service

        return None

    def merge_with_host(self, other: Self):
        """
        Merges other host with this one, respecting trusted fields.

        Parameters
        ----------
        other: Host
            Host to be merged with self
        """

        if not self.address:
            self.address = other.address
        else:
            self.address.update(other.address)

        # Handle hostnames with trust priority
        if "hostname" in other.trusted_fields and other.hostnames:
            # Other has trusted hostnames, use them
            self.hostnames = (
                other.hostnames.copy()
                if isinstance(other.hostnames, SortedSet)
                else SortedSet(other.hostnames)
            )
            self.trusted_fields.add("hostname")
        elif "hostname" not in self.trusted_fields:
            # Self doesn't have trusted hostnames, union them
            self.hostnames.update(other.hostnames)
        # else: self has trusted hostnames, keep them and ignore other

        # Merge services
        self.add_services(other.services, prioritize_self=True)

        # Handle OS with trust priority
        if "os" in other.trusted_fields and other.os:
            # Other has trusted OS, use it
            self.os = (
                other.os.copy()
                if isinstance(other.os, SortedSet)
                else SortedSet(other.os)
            )
            self.trusted_fields.add("os")
        elif "os" not in self.trusted_fields and not self.os:
            # Self has no OS and it's not trusted, use other's
            self.os = other.os
        # else: self has trusted OS or already has OS, keep it

        # Merge custom fields
        for key, values in other.custom_fields.items():
            if key in other.trusted_fields and values:
                self.custom_fields[key] = values.copy()
                self.trusted_fields.add(key)
            elif key in self.trusted_fields:
                pass
            elif key not in self.custom_fields:
                self.custom_fields[key] = values.copy()
            else:
                self.custom_fields[key].update(values)

    def union_with_host(self, other: Self):
        """
        Combine other host with this one.

        Parameters
        ----------
        other : Self
            Host to be combined with this one.
        """

        if not self.address:
            self.address = other.address
        else:
            self.address.update(other.address)

        # Union hostnames and services
        self.hostnames.update(other.hostnames)
        self.add_services(other.services)

        # Union os list
        self.os.update(other.os)

        # Union custom fields
        for key, values in other.custom_fields.items():
            if key in other.trusted_fields and values:
                self.custom_fields[key] = values.copy()
                self.trusted_fields.add(key)
            elif key not in self.trusted_fields:
                if key not in self.custom_fields:
                    self.custom_fields[key] = values.copy()
                else:
                    self.custom_fields[key].update(values)

    def identifier(self) -> str:
        """
        Identifier of the host, for user interaction (e.g. merge file).

        This will be the hosts address, or if it has none, the hosts hostname.

        Returns
        -------
        str
            IP address or else hostname of the host
        """

        if self.address:
            return next(iter(self.address))  # Use first address
        if len(self.hostnames) > 1:
            printer.warning(
                f"Using first hostname but several available: {self.hostnames}"
            )
        return next(iter(self.hostnames))

    def get_collisions(self) -> dict:
        """
        Returns a dictionary of collisions, ready to be printed into a merge
        file.
        """

        collisions: dict[str, Any] = {}

        if len(self.os) > 1:
            collisions["os"] = self.os

        for service in self.services:
            service_collisions: dict[str, SortedSet[str]] = {}
            # Multiple service names
            if len(service.service_names) > 1:
                service_collisions["service_names"] = service.service_names
            # Multiple banners
            if len(service.banners) > 1:
                service_collisions["banners"] = service.banners

            if service_collisions:
                # Create section for tcp/udp ports if not yet existent
                if f"{service.protocol}_ports" not in collisions:
                    collisions[f"{service.protocol}_ports"] = {}
                # Add section for services port
                collisions[f"{service.protocol}_ports"][service.port] = (
                    service_collisions
                )

        return collisions

    def sort(self):
        """
        Sorts the host attributes.
        """
        self.address = SortedSet(self.address)
        self.hostnames = SortedSet(self.hostnames)
        self.os = SortedSet(self.os)
        self.services.sort(key=lambda s: s.port)

    def __repr__(self) -> str:
        """
        Print host for testing purposes.
        """

        s = "\n"
        s += " ".join(self.address) + "\n"
        s += "~ Hostnames:\n" + f"    {self.hostnames}\n"
        s += "~ OS:\n" + f"    {self.os}\n"
        s += "~ Services:\n"
        for service in self.services:
            s += textwrap.indent(f"{service}\n", "    ")

        return s

    def __str__(self) -> str:
        return self.__repr__()
