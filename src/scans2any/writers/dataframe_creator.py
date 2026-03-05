"""Convert infrastructure objects to pandas DataFrames for unified writer processing."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    # Only imported for type hints; runtime import is deferred inside each
    # function to avoid loading pandas/numpy at startup (saves ~350 ms).
    import pandas as pd

from scans2any.internal import Infrastructure, printer


def create_dataframes(
    infra: Infrastructure,
    *,
    columns: tuple[str, ...],
    multi_table: bool,
    merge_symbol: str,
) -> list[pd.DataFrame]:
    """
    Convert the internal representation of the infrastructure
    into pandas DataFrames.

    Parameters
    ----------
    infra : Infrastructure
        The infrastructure to convert
    columns : tuple[str, ...]
        The columns to include in the output
    multi_table : bool, optional
        Whether to create mutli table for all hosts, by default False
    merge_symbol : str, optional
        Symbol to use when merging multiple values, by default "<br>"

    Returns
    -------
    list[pd.DataFrame]
        A list of pandas DataFrames. If multi_table is True, the list contains
        only one DataFrame. Otherwise, it contains one DataFrame per host.
    """

    if multi_table:
        return _create_multi_tables(infra, columns=columns, merge_symbol=merge_symbol)
    return [_create_single_table(infra, columns=columns, merge_symbol=merge_symbol)]


def _create_multi_tables(
    infra: Infrastructure, *, columns: tuple[str, ...], merge_symbol: str
) -> list[pd.DataFrame]:
    """
    Create one pandas DataFrame per host.
    """
    # Deferred import: keeps pandas/numpy out of the startup critical path.
    import pandas as pd

    dataframes = []

    # Define which columns belong in the header and which in the row data
    header_keys = {"IP-Addresses", "Hostnames", "OS"}
    row_keys = {"Ports", "Services", "Banners"}

    for host in infra.hosts:
        ip = merge_symbol.join(host.address) or ""
        hostnames = merge_symbol.join(h for h in host.hostnames if h)
        os_info = str(next(iter(host.os))) if host.os else ""

        ports = []
        services = []
        banners = []
        custom_row_values = {
            col: [] for col in columns if col not in header_keys and col not in row_keys
        }

        for service in host.services:
            banners.append(service.banners[0] if service.banners else "")
            services.append(service.service_names[0] if service.service_names else "")
            ports.append(f"{service.port}/{service.protocol}")
            for col in custom_row_values:
                if col in service.custom_fields:
                    custom_row_values[col].append(
                        merge_symbol.join(str(v) for v in service.custom_fields[col])
                    )
                else:
                    custom_row_values[col].append("")

        header_values = []
        row_values: dict[str, list | str] = {}
        for col in columns:
            if col in header_keys:
                if col == "IP-Addresses":
                    header_values.append(ip)
                elif col == "Hostnames":
                    header_values.append(hostnames)
                elif col == "OS":
                    header_values.append(os_info)
            elif col in row_keys:
                if col == "Ports":
                    row_values[col] = ports
                elif col == "Services":
                    row_values[col] = services
                elif col == "Banners":
                    row_values[col] = banners
            else:
                if col in host.custom_fields:
                    header_values.append(
                        merge_symbol.join(str(v) for v in host.custom_fields[col])
                    )
                else:
                    row_values[col] = custom_row_values[col]

        # if only header_values, show only first line
        rows_len = 0 if not row_values else len(ports)

        # Add empty values to maintain column structure
        while len(header_values) > len(row_values):
            row_values[str(len(row_values))] = ""

        while len(row_values) > len(header_values):
            header_values.append("")

        df = pd.DataFrame(row_values, index=range(0, rows_len))
        df.columns = pd.Index(header_values)
        dataframes.append(df)

    return dataframes


def _create_single_table(
    infra: Infrastructure, *, columns: tuple[str, ...], merge_symbol: str
) -> pd.DataFrame:
    """
    Create a single pandas DataFrame for all hosts.
    """
    # Deferred import: keeps pandas/numpy out of the startup critical path.
    import pandas as pd

    rows = []

    for host in infra.hosts:
        ip = merge_symbol.join(host.address) or ""
        hostnames = merge_symbol.join(h for h in host.hostnames if h)
        os_info = str(next(iter(host.os))) if host.os else ""

        ports_list = []
        services_list = []
        banners_list = []
        custom_fields_list = {
            col: []
            for col in columns
            if col
            not in ("IP-Addresses", "Hostnames", "OS", "Ports", "Services", "Banners")
        }

        for s in host.services:
            ports_list.append(f"{s.port}/{s.protocol}")
            services_list.append(" ".join(s.service_names))
            banners_list.append(s.banners[0] if s.banners else "")
            for col in custom_fields_list:
                if col in s.custom_fields:
                    custom_fields_list[col].append(
                        merge_symbol.join(str(v) for v in s.custom_fields[col])
                    )
                else:
                    custom_fields_list[col].append("")

        ports = merge_symbol.join(ports_list)
        services = merge_symbol.join(services_list)
        banners = merge_symbol.join(banners_list)

        row = {}
        for col in columns:
            if col == "IP-Addresses":
                row[col] = ip
            elif col == "Hostnames":
                row[col] = hostnames
            elif col == "OS":
                row[col] = os_info
            elif col == "Ports":
                row[col] = ports
            elif col == "Services":
                row[col] = services
            elif col == "Banners":
                row[col] = banners
            else:
                if col in host.custom_fields:
                    row[col] = merge_symbol.join(
                        str(v) for v in host.custom_fields[col]
                    )
                else:
                    row[col] = merge_symbol.join(custom_fields_list[col])

        rows.append(row)

    df = pd.DataFrame(rows)
    printer.success(f"Created dataframe with {len(rows)} hosts")
    return df


# For CSV and other formats that need flattened rows (one row per service)
def create_flat_dataframe(
    infra: Infrastructure,
    *,
    columns: tuple[str, ...],
    merge_symbol: str,
) -> pd.DataFrame:
    """
    Create a flattened DataFrame with one row per service.
    Useful for CSV and other row-based formats.
    """
    # Deferred import: keeps pandas/numpy out of the startup critical path.
    import pandas as pd

    rows = []

    for host in infra.hosts:
        address = merge_symbol.join(host.address) or ""
        hostnames = merge_symbol.join(h for h in host.hostnames if h)
        os_info = str(next(iter(host.os))) if host.os else ""

        host_row_base = {}
        for col in columns:
            if col == "IP-Addresses":
                host_row_base[col] = address
            elif col == "Hostnames":
                host_row_base[col] = hostnames
            elif col == "OS":
                host_row_base[col] = os_info
            elif (
                col not in ("Ports", "Services", "Banners")
                and col in host.custom_fields
            ):
                host_row_base[col] = merge_symbol.join(
                    str(v) for v in host.custom_fields[col]
                )

        if host.services:
            for service in host.services:
                row = {}
                for col in columns:
                    if col in host_row_base:
                        row[col] = host_row_base[col]
                    elif col == "Ports":
                        row[col] = f"{service.port}/{service.protocol}"
                    elif col == "Services":
                        row[col] = merge_symbol.join(service.service_names)
                    elif col == "Banners":
                        row[col] = merge_symbol.join(service.banners)
                    else:
                        row[col] = merge_symbol.join(
                            str(v) for v in service.custom_fields.get(col, [])
                        )
                rows.append(row)
        else:
            # Host with no services
            row = {}
            for col in columns:
                row[col] = host_row_base.get(col, "")
            rows.append(row)

    df = pd.DataFrame(rows)
    printer.success(f"Created flat dataframe with {len(rows)} rows")
    return df


def create_data_unmerged(
    infra: Infrastructure,
    *,
    columns: tuple[str, ...],
) -> dict:
    host_dict = {}
    unknown_counter = 0
    for host in infra.hosts:
        ip = next(iter(host.address)) if host.address else f"unknown_{unknown_counter}"
        if not host.address:
            unknown_counter += 1

        ip_infos: dict[str, list | dict] = {}
        host_dict[ip] = ip_infos

        processed_services = False
        for col in columns:
            if col == "IP-Addresses" and len(host.address) > 1:
                ip_infos[col.lower()] = list(host.address)
            elif col == "Hostnames":
                ip_infos[col.lower()] = list(host.hostnames)
            elif col == "OS":
                ip_infos[col.lower()] = list(host.os)
            elif col in ("Ports", "Services", "Banners") and not processed_services:
                processed_services = True
                tcp_ports = {}
                udp_ports = {}

                # Pre-calculate which columns to extract for services
                service_cols = []
                for c in columns:
                    if c == "Services":
                        service_cols.append(("service_names", "service_names"))
                    elif c == "Banners":
                        service_cols.append(("banners", c.lower()))
                    elif c not in ("IP-Addresses", "Hostnames", "OS", "Ports"):
                        service_cols.append((c, c))

                for service in host.services:
                    service_row = {}
                    for attr_name, dict_key in service_cols:
                        if attr_name == "service_names":
                            service_row[dict_key] = list(service.service_names)
                        elif attr_name == "banners":
                            service_row[dict_key] = list(service.banners)
                        elif attr_name in service.custom_fields:
                            service_row[dict_key] = list(
                                service.custom_fields[attr_name]
                            )

                    if service.protocol == "tcp":
                        tcp_ports[service.port] = service_row
                    elif service.protocol == "udp":
                        udp_ports[service.port] = service_row
                ip_infos["tcp_ports"] = tcp_ports
                ip_infos["udp_ports"] = udp_ports
            elif (
                col not in ("Ports", "Services", "Banners")
                and col in host.custom_fields
            ):
                ip_infos[col] = list(host.custom_fields[col])

    return host_dict


def create_dataframe_unmerged(
    infra: Infrastructure,
    *,
    columns: tuple[str, ...],
) -> pd.DataFrame:
    # Deferred import: keeps pandas/numpy out of the startup critical path.
    import pandas as pd

    host_dict = create_data_unmerged(infra, columns=columns)
    return pd.DataFrame(host_dict)
