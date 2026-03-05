"""Service data model representing a single network service on a host."""

from typing import Self

from pydantic import BaseModel, ConfigDict, Field

from scans2any.internal import printer
from scans2any.internal.sorted_set import SortedSet


class OverridingNoConflictError(Exception):
    """
    No conflict in service name / banner, yet trying to override in merge.
    """

    def __init__(self, port: int, *, service_name: bool, banners: bool, msg: str = ""):
        super().__init__(msg)

        self.port = port
        self.service_name = service_name
        self.banners = banners

    def print_warning(self, hostname: str):
        if self.service_name:
            printer.warning(
                f"Overriding {hostname} port {self.port}'s service name during merge, even though there were no conflicts."
            )
        if self.banners:
            printer.warning(
                f"Overriding {hostname} port {self.port}'s banners during merge, even though there were no conflicts."
            )


class Service(BaseModel):
    """
    Internal representation of a service run by a host.

    Attributes
    ----------
    port : int
        Numerical port of the service
    protocol: str
        tcp/udp
    service_names: SortedSet[str]
        Service names, e.g. `http`, `ssh`. A SortedSet of service names, containing
        multiple entries when there have been service name collisions.
    banners: SortedSet[str]
        Additional information about the service, e.g. `Apache httpd x.y`
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    port: int
    protocol: str
    service_names: SortedSet[str]
    banners: SortedSet[str]
    trusted_fields: set[str] = Field(default_factory=set)
    custom_fields: dict[str, set] = Field(default_factory=dict)

    def merge_with_service(self, other: Self):
        """
        Merges this service with the specified service, respecting trusted fields.

        Uses this service (self) as priority to solve merge conflicts, unless
        the other service has trusted fields.

        Should not be called on services with different ports/protocols.

        Parameters
        ----------
        other : Self
            Service object to be merged with this service
        """

        assert self.port == other.port
        assert self.protocol == other.protocol

        raise_service_name_override = False
        raise_banners_override = False

        # Handle service_names with trust priority
        if "service_names" in other.trusted_fields and other.service_names:
            # Other has trusted service names, use them
            self.service_names = other.service_names.copy()
            self.trusted_fields.add("service_names")
        elif "service_names" in self.trusted_fields:
            # Self has trusted service names, keep them
            pass
        elif not self.service_names:
            # Self has no service names, use other's
            self.service_names = other.service_names
        elif len(other.service_names) == 1:
            raise_service_name_override = True

        # Handle banners with trust priority
        if "banners" in other.trusted_fields and other.banners:
            # Other has trusted banners, use them
            self.banners = other.banners.copy()
            self.trusted_fields.add("banners")
        elif "banners" in self.trusted_fields:
            # Self has trusted banners, keep them
            pass
        elif not self.banners:
            # Self has no banners, use other's
            self.banners = other.banners
        elif len(other.banners) == 1:
            raise_banners_override = True

        # Handle protocol with trust priority
        if "protocol" in other.trusted_fields and other.protocol:
            self.protocol = other.protocol
            self.trusted_fields.add("protocol")

        # Raise exceptions on override without conflict (only if no trust involved)
        if (
            (raise_service_name_override or raise_banners_override)
            and "service_names" not in self.trusted_fields
            and "service_names" not in other.trusted_fields
            and "banners" not in self.trusted_fields
            and "banners" not in other.trusted_fields
        ):
            raise OverridingNoConflictError(
                port=self.port,
                service_name=raise_service_name_override,
                banners=raise_banners_override,
            )

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

    def union_with_service(self, other: Self):
        """
        Combine services with same `port` and `protocol`, respecting trusted fields.

        Unions service names and banners unless one source is trusted.

        Should not be called on services with different ports/protocols.

        Parameters
        ----------
        other : Self
            Other service instance to be integrated into this one
        """

        assert self.port == other.port
        assert self.protocol == other.protocol

        # Handle service_names with trust priority
        if "service_names" in other.trusted_fields and other.service_names:
            self.service_names = other.service_names.copy()
            self.trusted_fields.add("service_names")
        elif "service_names" not in self.trusted_fields:
            self.service_names.update(other.service_names)

        # Handle banners with trust priority
        if "banners" in other.trusted_fields and other.banners:
            self.banners = other.banners.copy()
            self.trusted_fields.add("banners")
        elif "banners" not in self.trusted_fields:
            self.banners.update(other.banners)

        # Handle protocol with trust priority
        if "protocol" in other.trusted_fields:
            self.protocol = other.protocol
            self.trusted_fields.add("protocol")

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

    def __repr__(self) -> str:
        """
        Print service for testing purposes.
        """

        s = f"{self.port}/{self.protocol} - {self.service_names}"
        if self.banners:
            s += f"\n    {self.banners}"
        return s

    def __str__(self) -> str:
        return self.__repr__()


def get_port_by_service(service: str, protocol: str) -> int:
    """
    Get default port associated with the specified service + protocol.

    Parameters
    ----------
    service : str
        e.g. `https`
    protocol : str
        `tcp`/`udp`

    Returns
    -------
    int
        Default port, associated with the specified service + protocol
    """

    tcp_map = {"http": 80, "https": 443}

    if protocol == "tcp":
        return tcp_map.get(service, 80)  # Default to port 80 if not found
    raise Exception("protocol not defined")
