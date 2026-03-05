"""General-purpose utility functions shared across the scans2any codebase."""

import argparse
import functools
import ipaddress
import json
import re
from pathlib import Path
from typing import TypeVar

from partial_json_parser import loads as json_partial_loads

from scans2any.internal import printer

# Built-in column names (normalized lowercase -> canonical display name).
# Custom columns contributed by parsers are NOT listed here; they are
# collected at startup via parsers.parser_custom_columns.
VALID_COLUMNS = {
    "ip-addresses": "IP-Addresses",
    "hostnames": "Hostnames",
    "ports": "Ports",
    "services": "Services",
    "banners": "Banners",
    "os": "OS",
}


def validate_columns(
    columns: tuple[str, ...],
    extra_columns: dict[str, str] | None = None,
    default_columns: tuple[str, ...] | None = None,
    *,
    allow_any: bool = False,
) -> tuple[str, ...]:
    """
    Validates column names and normalizes them.

    Parameters
    ----------
    columns : tuple[str, ...]
        The columns specified by the user.
    extra_columns : dict[str, str] | None
        Additional valid columns contributed by parsers
        (normalized-lowercase -> canonical name).
    allow_any : bool
        When True, unknown column names are passed through as-is instead of
        raising an error (used when an open-format parser like json_parser is
        available and may produce arbitrary custom fields).

    Returns
    -------
    tuple[str, ...]
        Validated and normalized column names.

    Raises
    ------
    argparse.ArgumentTypeError
        When a column name is not known and allow_any is False.
    """
    all_known: dict[str, str] = {**VALID_COLUMNS, **(extra_columns or {})}

    if not columns:
        return tuple(default_columns) if default_columns else tuple()

    valid_columns = []

    first_col = columns[0]
    if first_col.startswith(("+", "-")):
        valid_columns = (
            list(default_columns) if default_columns else list(all_known.values())
        )

    for col in columns:
        operator = None
        if col.startswith(("+", "-")):
            operator = col[0]
            col = col[1:]

        col_lower = col.lower()
        resolved_col = None

        if col_lower in all_known:
            resolved_col = all_known[col_lower]
        elif allow_any:
            resolved_col = col

        if resolved_col:
            if operator == "-":
                if resolved_col in valid_columns:
                    valid_columns.remove(resolved_col)
            elif operator == "+":
                if resolved_col not in valid_columns:
                    valid_columns.append(resolved_col)
            else:
                if resolved_col not in valid_columns:
                    valid_columns.append(resolved_col)
        else:
            known_names = ", ".join(sorted(all_known.values()))
            raise argparse.ArgumentTypeError(
                f"Unknown column '{col}'. Known columns: {known_names}"
            )

    if not valid_columns:
        printer.warning("No valid columns specified. Using default columns.")
        return tuple(default_columns) if default_columns else tuple(all_known.values())

    return tuple(valid_columns)


def is_valid_ip(address: str) -> bool:
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False


def is_valid_ipv6(address: str | None) -> bool:
    try:
        ipaddress.IPv6Address(address)
        return True
    except ValueError:
        return False


def find_os(os_detection_result: str) -> str | None:
    """
    Extracts information from the given string (coming from some kind of
    os-detection (e.g. Nessus) result) to return a simplified OS result, if
    possible.
    """

    # OS detection mapping with variants simplified to core categories
    os_map = {
        # Linux distributions
        "linux": "linux",
        "centos": "linux",
        "arch": "linux",
        "manjaro": "linux",
        "ubuntu": "linux",
        "debian": "linux",
        "fedora": "linux",
        "red hat": "linux",
        "gentoo": "linux",
        "suse": "linux",
        # Windows variants
        "windows": "windows",
        "win": "windows",
        "microsoft": "windows",
        # macOS variants
        "macos": "macos",
        "mac os": "macos",
        "os x": "macos",
        "darwin": "macos",
        "mac_os": "macos",
        "mac-os": "macos",
        "macintosh": "macos",
        # FreeBSD
        "freebsd": "bsd",
        "openbsd": "bsd",
        "netbsd": "bsd",
    }

    # Convert the detection result to lowercase for case-insensitive matching
    os_detection_result = os_detection_result.lower()

    # Search for any OS indicator in the result
    for key, value in os_map.items():
        if key in os_detection_result:
            return value

    return None


def trustworthiness_os(info_origin: str) -> int:
    """
    Union OS lists based on info_origins
    Return trustworthiness of info_origin

    Parameters
    ----------
    info_origin : str
        The origin of the information

    Returns
    -------
    int
        Trustworthiness of the origin
    """
    os_prio_list = (
        "Nmap",
        "Nessus",
        "NetExec",
        "Bloodhound",
    )  # from least to most trustworthy
    if info_origin in os_prio_list:
        return os_prio_list.index(info_origin) + 1
    return 0


T = TypeVar("T")


class FileError(Exception):
    pass


class PartialParsingFailedError(Exception):
    pass


def is_special_fd(filename: str | Path) -> bool:
    return bool(re.match(r"^(?:/proc/self/fd/|/dev/fd/)\d+$", str(filename)))


def read_json[T](filename: str | Path, return_type: type[T]) -> T:
    file_path = Path(filename)
    if not is_special_fd(str(filename)) and (
        not file_path.is_file() or file_path.stat().st_size == 0
    ):
        raise FileError(f"File {filename} is empty or does not exist.")

    with open(filename) as file:
        content = file.read()

    try:
        return json.loads(content)
    except json.JSONDecodeError as e:
        # Fallback to partial parsing
        try:
            return json_partial_loads(content)  # type: ignore[return-value]
        except Exception as f:
            raise PartialParsingFailedError(
                f"JSON parsing '{e}' and partial parsing '{f}' failed."
            ) from e


_DOMAIN_REGEX = re.compile(
    r"^(?!-)(?:[a-zA-Z0-9-]{1,63}|(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,})$"
)


def match_dns(dns: str) -> bool:
    """
    Check if a given string is a valid DNS name.

    Parameters
    ----------
    dns : str
        The string to be checked.

    Returns
    -------
    bool
        True if the string is a valid DNS name, False otherwise.
    """
    return _DOMAIN_REGEX.match(dns) is not None


_FQDN_REGEX = re.compile(r"^(?!\-)([a-zA-Z0-9\-]{1,63}\.)+[a-zA-Z]{2,}$")


def match_fqdn(dns: str) -> bool:
    """
    Check if a given string is a valid DNS name.

    Parameters
    ----------
    dns : str
        The string to be checked.

    Returns
    -------
    bool
        True if the string is a valid FQDN name, False otherwise.
    """
    return _FQDN_REGEX.match(dns) is not None


@functools.lru_cache(maxsize=32)
def _get_cleanup_regex(chars_to_escape: str) -> re.Pattern:
    escaped_chars = re.escape(chars_to_escape)
    # Construct a regex pattern that matches any of the characters to be escaped
    # The regex looks for any character in escaped_chars that is not already preceded by a backslash
    pattern = r"(?<!\\)([" + escaped_chars + "])"
    return re.compile(pattern)


def cleanup(string: str, chars_to_escape: str) -> str:
    regex = _get_cleanup_regex(chars_to_escape)
    # Replace any unescaped special character with its escaped version
    return regex.sub(r"\\\1", string)
