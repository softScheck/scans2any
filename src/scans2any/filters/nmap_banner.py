"""Normalize and filter nmap service banners to reduce information overload."""

import re
from typing import Any

from scans2any.internal import Service, SortedSet

PRIORITY = 1

POSSIBLE_KEYS = [
    "product",
    "version",
    "extrainfo",  # difficult to filter
    "ostype",  # os detection
    "hostname",
    "devicetype",
]


def apply_filter(service: Service, args: Any) -> None:
    """Filters a service's nmap banners, to reduce information overload."""

    # Banners keys are filtered by these rules
    key_filter = ("product", "version", "devicetype")

    filtered_banners: SortedSet = SortedSet()
    to_remove: SortedSet = SortedSet()

    for banner in service.banners:
        if _is_nmap_banner(banner):
            banner_keys = _make_dict_from_nmap_banner(banner)
            filtered_banners.add(_build_banner(banner_keys, key_filter))
            to_remove.add(banner)

    # Update banners in a single operation
    service.banners -= to_remove
    service.banners |= filtered_banners


def _is_nmap_banner(banner: str) -> bool:
    """Check if banner is an nmap banner by looking for characteristic keys."""
    return any(f"{key}: " in banner for key in POSSIBLE_KEYS)


def _make_dict_from_nmap_banner(banner: str) -> dict[str, str]:
    """
    Turn nmap banner into dictionary with available keys. For instance turn
    `product: webserver version: 1.9` into a dict {"product":"1.9"}
    """
    # Pattern explanation: We expect a string similar to "key1: content for key
    # 1 key2: content for key2" where key1 and key2 are part of
    # "POSSIBLE_KEYS".
    # We want to create a dictionary with they keys and
    # contents assorted. This leads to the following pattern with three match
    # groups:
    # (key1): (content for key1)(<either more of the same or the end of the
    # string>)
    pattern = r"({0}): (.*?)(?=\s(?:{0}):|\s*$)".format("|".join(POSSIBLE_KEYS))

    return {key: value for key, value in re.findall(pattern, banner)}


def _build_banner(available_keys: dict[str, str], key_filter: tuple[str, ...]) -> str:
    """
    Build banner in consistent format:
    `product` `version` (`devicetype`)
    """
    filtered_keys = {k: v for k, v in available_keys.items() if k in key_filter}

    parts = []

    # Handle product and version specifically for the format
    if filtered_keys.get("product"):
        product = filtered_keys["product"]

        if filtered_keys.get("version"):
            parts.append(f"{product}/{filtered_keys['version']}")
        else:
            parts.append(product)

    elif filtered_keys.get("version"):
        parts.append(filtered_keys["version"])

    # Add devicetype in parentheses if present
    if filtered_keys.get("devicetype"):
        parts.append(f"({filtered_keys['devicetype']})")

    return " ".join(parts)
