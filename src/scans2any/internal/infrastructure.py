"""Infrastructure data model representing a collection of scanned hosts."""

import ipaddress
import os
import tempfile
import textwrap
from pathlib import Path
from typing import Self

import yaml
from pydantic import BaseModel, ConfigDict, Field

from scans2any.internal import Host, printer
from scans2any.internal.clustering import cluster_hosts
from scans2any.internal.host import HostIntegrationError
from scans2any.internal.sorted_set import SortedSet

try:
    from yaml import CSafeDumper as SafeDumper
    from yaml import CSafeLoader as SafeLoader
except ImportError:
    from yaml import SafeDumper, SafeLoader


# --- Performance helpers for merge file generation ---
def _represent_sortedset(dumper, data):  # pragma: no cover - simple adapter
    return dumper.represent_list(list(data))


if SortedSet not in SafeDumper.yaml_representers:
    yaml.add_representer(SortedSet, _represent_sortedset, Dumper=SafeDumper)

_MERGEFILE_HEADER = "# scans2any: merge file\n\n"
_AUTOMERGE_SECTION_HEADER = (
    "# Automatic merging rules.\n"
    "#\n"
    "# if any of the listed combinations of service names [and port] (e.g. `http` and\n"
    "# `www`) are found as service names for the same port, the key is used as the\n"
    "# conflict solving service name.\n"
)
_AUTOMERGE_TEMPLATE = (
    "auto-merge:\n"
    "#-   service-names:\n"
    "#    - http\n"
    "#    - https\n"
    "#    port: 443\n"
    "#    key:\n"
    "#    - https\n"
    "#-   service-names:\n"
    "#    - http\n"
    "#    - https\n"
    "#    port: 80\n"
    "#    key:\n"
    "#    - http\n"
)
_MANUAL_SECTION_HEADER = (
    "\n# Manual merging rules.\n"
    "#\n# Make sure there is only one service name and banner for each port left\n"
    "# then execute scans2any again with option `--merge-file filename`\n"
)
_CUSTOM_SECTION_TEMPLATE = (
    "\n# Custom entries\n"
    "#\n"
    "# Add custom entries in this way:\n"
    "custom-entries:\n"
    "#    1.1.1.1:\n"
    "#        hostnames:\n"
    "#           -   test.company.com\n"
    "#           -   test2.company.com\n"
    "#        os: linux\n"
    "#        ports:\n"
    "#           -   port: 1111/tcp\n"
    "#               service-name: test\n"
    "#               banner: Test description\n"
    "#           -   port: 2222/udp\n"
    "#               service-name: test2\n"
    "#               banner: Test description 2\n"
    "#    2.2.2.2:\n"
    "#        hostnames:\n"
    "#           -   asdf.company.local\n"
    "#        os: bsd\n"
    "#        ports:\n"
    "#           -   port: 333/tcp\n"
    "#               service-name: test\n"
    "#               banner: Test description 3"
)


def _validate_and_split_rules(
    ruleset: list[dict],
) -> tuple[list[dict], list[dict]]:
    """Validate auto-merge rules and split into OS rules and service/banner rules.

    Returns two lists: (os_rules, service_rules).  Each entry is a normalised
    dict ready for fast matching inside ``auto_merge``.
    """
    os_rules: list[dict] = []
    service_rules: list[dict] = []

    for rule in ruleset:
        if "key" not in rule:
            printer.failure(f"Malformed rule in ruleset: {rule}")
            printer.failure("'key' is required in each rule. Skipping...")
            continue

        has_os = "os" in rule
        has_svc = "service-names" in rule
        has_ban = "banners" in rule

        if not (has_os or has_svc or has_ban):
            printer.failure(f"Malformed rule in ruleset: {rule}")
            printer.failure(
                "At least one of 'service-names', 'os', or 'banners' is needed. Skipping..."
            )
            continue

        key = rule["key"]

        # Pure OS rule  →  os_rules list
        if has_os and not has_svc and not has_ban:
            os_set = frozenset(rule["os"])
            if not os_set:
                printer.failure(
                    f"Malformed rule: empty 'os' list in {rule}. Skipping..."
                )
                continue
            os_rules.append({"key": key, "os": os_set, "cnt": 0})
            continue

        # Service-name and/or banner rule  →  service_rules list
        svc_names: frozenset[str] | None = None
        if has_svc:
            svc_names = frozenset(rule["service-names"])
            if not svc_names:
                printer.failure(
                    f"Malformed rule: empty 'service-names' list in {rule}. Skipping..."
                )
                continue

        banners: tuple[str, ...] | None = None
        if has_ban:
            banners = tuple(sorted(set(rule["banners"])))

        service_rules.append(
            {
                "key": key,
                "service_names": svc_names,
                "port": rule.get("port"),
                "ports": frozenset(rule["ports"]) if "ports" in rule else None,
                "banners": banners,
                "cnt": 0,
            }
        )

    return os_rules, service_rules


class Infrastructure(BaseModel):
    """
    Internal representation of parsed infrastructure scans.

    No two hosts with the same ip address possible.

    Attributes
    ----------
    hosts : list[Host]
        List of scanned and available hosts
    identifier : str
        Additional information, like `Nmap scan infrastructure`
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    hosts: list[Host] = Field(default_factory=list)
    identifier: str = ""
    trusted_fields: dict[str, list[str]] = Field(default_factory=dict)

    def __init__(
        self,
        hosts: list[Host] | None = None,
        identifier: str = "",
        trusted_fields: dict[str, list[str]] | None = None,
    ):
        super().__init__(identifier=identifier, trusted_fields=trusted_fields or {})
        if hosts is not None:
            self.add_hosts(hosts)

    def add_host(self, new_host: Host, *, prioritize_self: bool = False):
        """
        Adds a new host to the infrastructure OR integrates it to an existing
        host with the same ip address or at most one ip address and matching
        hostnames.

        Propagates trusted_fields from Infrastructure to the host and its services.

        Optionally, we can use this infrastructure as priority, to avoid
        collisions, i. e. multiple service names and/or banners.

        Parameters
        ----------
        new_host: Host
            Host to be added/integrated
        prioritize_self : bool
            Call `merge_with_host` instead of `union_with_host` on host, if it
            has to be integrated into an existing host of `self`.
        """

        try:
            assert type(new_host) is Host
        except AssertionError:
            printer.warning(f"Skipped attempt to add host of type {type(new_host)}")
            return

        # Propagate trusted_fields from Infrastructure to Host
        if "host" in self.trusted_fields:
            for field in self.trusted_fields["host"]:
                new_host.trusted_fields.add(field)

        # Propagate trusted_fields to all services
        if "service" in self.trusted_fields:
            for service in new_host.services:
                for field in self.trusted_fields["service"]:
                    service.trusted_fields.add(field)

        # Fast O(n) linear scan for single-host additions (avoids cluster_hosts
        # overhead of list copy + union-find + dict setup on every call).
        for host in self.hosts:
            if (host.address & new_host.address) or (
                host.hostnames & new_host.hostnames
            ):
                try:
                    if prioritize_self:
                        host.merge_with_host(new_host)
                        return
                    host.union_with_host(new_host)
                    return
                except HostIntegrationError as e:
                    printer.warning(str(e))
                    printer.warning(f"self: {host.address!s}, {host.hostnames!s}")
                    printer.warning(
                        f"other: {new_host.address!s}, {new_host.hostnames!s}"
                    )

        self.hosts.append(new_host)

    def add_hosts(self, new_hosts: list[Host], *, prioritize_self: bool = False):
        """
        Add new hosts to the infrastructure using cluster-based merging.

        Hosts sharing IP addresses or hostnames (transitively) are grouped into
        clusters.  Existing hosts (self) are preferred as the merge base so
        that their data takes priority when ``prioritize_self`` is set.

        Parameters
        ----------
        new_hosts: list[Host]
            List of hosts to be added
        prioritize_self: bool
            Use `merge_with_host` (priority) instead of `union_with_host`.
        """
        if not new_hosts:
            return

        # Propagate trusted_fields from Infrastructure to new hosts
        if "host" in self.trusted_fields:
            for new_host in new_hosts:
                for field in self.trusted_fields["host"]:
                    new_host.trusted_fields.add(field)

        if "service" in self.trusted_fields:
            for new_host in new_hosts:
                for service in new_host.services:
                    for field in self.trusted_fields["service"]:
                        service.trusted_fields.add(field)

        # Build combined host list
        all_hosts = self.hosts + new_hosts
        self_host_ids = {id(h) for h in self.hosts}

        clusters = cluster_hosts(all_hosts)
        merged: list[Host] = []

        for cluster in clusters:
            # Existing (priority) hosts first, then new hosts
            prio = [h for h in cluster if id(h) in self_host_ids]
            rest = [h for h in cluster if id(h) not in self_host_ids]
            ordered = prio + rest

            base_host = ordered[0]
            for h in ordered[1:]:
                try:
                    if prioritize_self:
                        base_host.merge_with_host(h)
                    else:
                        base_host.union_with_host(h)
                except HostIntegrationError as e:
                    printer.warning(str(e))
                    printer.warning(
                        f"self: {base_host.address!s}, {base_host.hostnames!s}"
                    )
                    printer.warning(f"other: {h.address!s}, {h.hostnames!s}")
                    merged.append(h)
            merged.append(base_host)

        self.hosts = merged

    def remove_host(self, hostip: str):
        """
        Remove host with given ip from the infrastructure if it has only one
        address. If it has multiple addresses, remove the specific address from
        the host.

        Parameters
        ----------
        hostip : str
            IP addresses
        """

        new_hosts = []
        for host in self.hosts:
            if hostip in host.address:
                if len(host.address) == 1:
                    continue
                else:
                    host.address.remove(hostip)
            new_hosts.append(host)
        self.hosts = new_hosts

    def get_host_by_address(self, hostip: str):
        """
        Returns host with the specified address or None.

        Parameters
        ----------
        hostip : str
            IP addresses
        """

        for host in self.hosts:
            if hostip in host.address:
                return host

        return None

    def merge_with_infrastructure(self, other: Self, ruleset: list[dict] | None = None):
        """High-performance prioritized merge of another infrastructure into self.

        Priority semantics (unchanged logically from legacy implementation):
        - Existing hosts (self) win on conflicting service names & banners.
        - Existing host OS kept if non-empty; otherwise adopt from other.
        - Addresses/hostnames are always unioned.

        This optimized version avoids O(n^2) host-by-host matching by building
        connected components (Union-Find) across self.hosts + other.hosts using
        shared IPs or hostnames, then performing one merge per component.
        """

        if self is not other and other.hosts:
            if not self.hosts:
                # Quick path: if self empty just clone other's hosts
                self.hosts = list(other.hosts)
            else:
                # Build combined host list
                all_hosts = self.hosts + other.hosts
                self_host_ids = {id(h) for h in self.hosts}

                clusters = cluster_hosts(all_hosts)
                merged: list[Host] = []

                for cluster in clusters:
                    prio = [h for h in cluster if id(h) in self_host_ids]
                    rest = [h for h in cluster if id(h) not in self_host_ids]

                    if prio:
                        base_host = prio[0]
                        for h in prio[1:] + rest:
                            base_host.merge_with_host(h)
                    else:
                        base_host = rest[0]
                        for h in rest[1:]:
                            base_host.union_with_host(h)

                    base_host.sort()
                    merged.append(base_host)

                self.hosts = merged

        # Apply rules post-merge
        if ruleset is not None:
            self.auto_merge(ruleset)

    def auto_merge(
        self,
        ruleset: list[dict] | None = None,
        *,
        quiet: bool = False,
        verbose: bool = False,
    ):
        """
        Automatic conflict solving using internal ruleset from config.

        If an optional ruleset is passed, it is used instead of the internal ruleset
        from the config.

        ruleset: list[dict]
            List of merging rules as in `merge-rules.yaml` to be applied.
        quiet: bool
            If True, suppress status spinner output.
        verbose: bool
            If True, keep status visible after completion.
        """
        with printer.status_section("Automatic Merging", quiet=quiet, verbose=verbose):
            if ruleset is None:
                config_path = Path(__file__).parent / "merge-rules.yaml"
                with open(config_path) as file:
                    config = yaml.load(file, Loader=SafeLoader)
                    ruleset = config.get("auto-merge", [])

            os_rules, service_rules = _validate_and_split_rules(ruleset)

            cnt_os = 0
            cnt_service = 0
            cnt_banner = 0

            for host in self.hosts:
                # --- OS rules (only checked per host, not per service) ---
                if os_rules and host.os:
                    host_os_set = frozenset(host.os)
                    for rule in os_rules:
                        if host_os_set == rule["os"]:
                            host.os = SortedSet(rule["key"])
                            host_os_set = frozenset(host.os)
                            cnt_os += 1
                            rule["cnt"] += 1

                # --- Service / banner rules ---
                if not service_rules:
                    continue

                for service in host.services:
                    svc_names = frozenset(service.service_names)
                    svc_banners = tuple(sorted(service.banners))

                    for rule in service_rules:
                        # Service-name matching (port constraints apply to
                        # both service-name and banner checks for this rule)
                        if rule["service_names"] is not None:
                            port = rule["port"]
                            if port is not None and service.port != port:
                                continue
                            ports = rule["ports"]
                            if ports is not None and service.port not in ports:
                                continue
                            if svc_names != rule["service_names"]:
                                continue

                            service.service_names = SortedSet(rule["key"])
                            svc_names = frozenset(service.service_names)
                            cnt_service += 1
                            rule["cnt"] += 1

                        if (
                            rule["banners"] is not None
                            and svc_banners == rule["banners"]
                        ):
                            service.banners = SortedSet(rule["key"])
                            svc_banners = tuple(sorted(service.banners))
                            cnt_banner += 1
                            rule["cnt"] += 1

            all_rules = os_rules + service_rules
            for rule in all_rules:
                if rule["cnt"] > 0:
                    printer.status(f"Applied rule '{rule['key']}' {rule['cnt']} times.")

            if cnt_os or cnt_service or cnt_banner:
                printer.success(
                    f"Successfully applied {cnt_os} OS, {cnt_service} service, and {cnt_banner} banner merge rules."
                )
            else:
                printer.info("No merge rules were applied.")

    def make_merge_file(
        self, *, passed_merge_file: bool, buffer_file: str = "BUFFER_FILE.json"
    ):
        """
        Create merge file if necessary (optimized).

        Collects collisions in a single pass, writes a structured merge file
        with large buffered chunks and avoids previously unused preserved vs
        altered separation (kept externally for compatibility if needed).

        Parameters
        ----------
        passed_merge_file:
            `True` if a merge file was passed. Needed for merge file creation.

        Raises
        ------
        ExistingMergeFile
            Merge file exists already and user did choose not to override it.
        NoCollisions
            No collisions found (probably called with `--merge-file` or with
            only a single input)
        """

        file_name = "MERGE_FILE.yaml"
        temp_merge_file = Path(tempfile.gettempdir()) / file_name

        # Single-pass collision collection using walrus operator
        collisions = {
            h.identifier(): c for h in self.hosts if (c := h.get_collisions())
        }

        if not collisions:
            return False

        printer.warning("Conflicts found in infrastructure.")

        # Don't override merge file without explicit consent
        if Path(file_name).exists():
            # If the existing merge file was not passed, there are probably not
            # many solved conflicts in it and the user may either override it
            # completely or leave it as it is.
            if not passed_merge_file:
                printer.warning(
                    f"Mergefile '{file_name}' already exists, "
                    + f" writing to temporary file {temp_merge_file} instead."
                )
                file_name = temp_merge_file
            else:
                # Merge file was passed but still has conflicts - create a new one
                # with remaining conflicts for the user to resolve
                printer.warning(
                    f"Mergefile '{file_name}' has remaining conflicts. "
                    f"Creating updated merge file with unresolved conflicts."
                )
                printer.debug(f"Collisions: {collisions}")
                # Don't exit - continue to write the updated merge file

        target_dir = Path(file_name).resolve().parent or Path(".")
        if not os.access(target_dir, os.W_OK):
            printer.warning(
                "No write access to current directory. Using temporary file."
            )
            file_name = str(temp_merge_file)

        # Currently no auto merge rules computed here (placeholder None)
        self.__write_merge_file(None, collisions, {}, file_name)
        printer.warning(
            "One or multiple unresolvable conflicts have been identified. "
            f"A Mergefile has been written to '{file_name}' and a "
            f"JSON Bufferfile has been written to '{buffer_file}'.\n"
            "Please edit the Mergefile to resolve the issues and then continue "
            f"with: scans2any --merge-file {file_name} --json {buffer_file}."
            "\nFor further documentation refer to: "
            "https://github.com/softScheck/scans2any/blob/main/docs/tutorial.md#merge-file"
        )
        return True

    def sort(self):
        """
        Sort hosts, i.e. sort services for each host and sort hosts by IP.
        """

        # Sorts the host attributes.
        for host in self.hosts:
            host.sort()
        # There might be hosts with only hostnames, they have to be sorted
        # separately. Sort by first hostname.
        only_hostname_hosts = [host for host in self.hosts if not host.address]
        for host in only_hostname_hosts:
            assert host.hostnames, "Host with no ip and no hostnames detected!!!"
        only_hostname_hosts.sort(key=lambda x: min(x.hostnames))
        # Sort remaining hosts by IP
        address_hosts = [host for host in self.hosts if host.address]
        address_hosts.sort(
            key=lambda x: min(
                map(
                    lambda addr: (
                        ipaddress.ip_address(addr).version,
                        int(ipaddress.ip_address(addr)),
                    ),
                    x.address,
                )
            )
        )
        # re-combine hosts
        self.hosts = address_hosts + only_hostname_hosts

    def cleanup_names(self, chars_to_escape: str):
        # Import cleanup locally to break circular dependency
        from scans2any.helpers.utils import cleanup

        # Function to clean and update names
        def clean_names(items, chars_to_escape):
            return SortedSet([cleanup(item, chars_to_escape) for item in items])

        # Apply cleanup to all hostnames and services
        for host in self.hosts:
            # Clean up hostnames using a list comprehension
            host.hostnames = clean_names(host.hostnames, chars_to_escape)

            # Clean up service names and banner in each service
            for service in host.services:
                service.service_names = clean_names(
                    service.service_names, chars_to_escape
                )
                service.banners = clean_names(service.banners, chars_to_escape)

    def __repr__(self) -> str:
        """
        Print infrastructure, for testing purposes.
        """

        s = ""
        for host in self.hosts:
            s += str(host)
        return s

    def __str__(self) -> str:
        return self.__repr__()

    def __write_merge_file(
        self,
        auto_merge_rules,
        manual_merge_altered_rules,
        manual_merge_preserved_rules,
        file_name: str | Path = "MERGE_FILE.yaml",
    ):
        """Write collisions to merge file in `yaml` format (optimized)."""

        parts: list[str] = []
        parts.append(_MERGEFILE_HEADER)
        parts.append(_AUTOMERGE_SECTION_HEADER)
        if auto_merge_rules is not None:
            parts.append(
                yaml.dump(
                    {"auto-merge": auto_merge_rules},
                    Dumper=SafeDumper,
                    indent=4,
                    sort_keys=False,
                )
            )
        else:
            parts.append(_AUTOMERGE_TEMPLATE)
        parts.append(_MANUAL_SECTION_HEADER)
        parts.append(
            yaml.dump(
                {"manual-merge": manual_merge_altered_rules},
                Dumper=SafeDumper,
                indent=4,
                sort_keys=True,
            )
        )
        if manual_merge_preserved_rules:
            preserved_block = yaml.dump(
                manual_merge_preserved_rules,
                Dumper=SafeDumper,
                indent=4,
                sort_keys=True,
            )
            parts.append(textwrap.indent(preserved_block, prefix="    "))
        parts.append(_CUSTOM_SECTION_TEMPLATE)

        with open(file_name, "w") as fh:
            fh.write("".join(parts))

    def merge_os_sources(self):
        from scans2any.helpers.utils import (
            trustworthiness_os,  # Local import to break circular dependency
        )

        """
        Merge os sources for each host using trustworthiness_os function. If a
        host has only one os source, it is kept. If a host has multiple os
        sources, the one with the highest trustworthiness is kept. If multiple
        sources have the same trustworthiness, all are kept.

        Attributes
        ----------
        host : Host
            Host with os votes.
        """

        for host in self.hosts:
            if not host.os:
                host.os = SortedSet()
                continue

            if len(host.os) == 1:
                host.os = SortedSet([next(iter(host.os))[0]])
            else:
                tally: dict[str, int] = {}
                for os in host.os:
                    if os[0] in tally:
                        tally[os[0]] += trustworthiness_os(os[1])
                    else:
                        tally[os[0]] = trustworthiness_os(os[1])

                max_score = max(tally.values())
                host.os = SortedSet(
                    [os for os, score in tally.items() if score == max_score]
                )
