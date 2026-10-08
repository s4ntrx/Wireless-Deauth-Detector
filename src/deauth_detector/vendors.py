from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache

from scapy.config import conf

MAC_PATTERN = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
BROADCAST = "ff:ff:ff:ff:ff:ff"
MULTICAST_BIT = 0x01
LOCALLY_ADMINISTERED_BIT = 0x02
MAX_LABEL_LENGTH = 32


@dataclass(frozen=True)
class VendorInfo:
    label: str
    kind: str


def _registered_name(mac: str) -> str | None:
    try:
        name = conf.manufdb._get_manuf(mac)
    except (AttributeError, KeyError, ValueError):
        return None
    return None if not name or name.lower() == mac else name


def _shorten(name: str) -> str:
    return name if len(name) <= MAX_LABEL_LENGTH else name[: MAX_LABEL_LENGTH - 1].rstrip() + "..."


@lru_cache(maxsize=8192)
def lookup_vendor(mac: str, virtual_interface: bool = False) -> VendorInfo:
    mac = mac.strip().lower().replace("-", ":")
    if not MAC_PATTERN.match(mac):
        return VendorInfo("Invalid address", "invalid")
    if mac == BROADCAST:
        return VendorInfo("Broadcast", "broadcast")

    first_octet = int(mac[:2], 16)
    if first_octet & MULTICAST_BIT:
        return VendorInfo("Multicast group", "multicast")

    if first_octet & LOCALLY_ADMINISTERED_BIT:
        if virtual_interface:
            base = f"{first_octet & ~LOCALLY_ADMINISTERED_BIT:02x}{mac[2:]}"
            name = _registered_name(base)
            if name:
                return VendorInfo(f"{_shorten(name)} (virtual interface)", "virtual")
        return VendorInfo("Locally administered", "local")

    name = _registered_name(mac)
    if name is None:
        return VendorInfo("Unknown vendor", "unknown")
    return VendorInfo(_shorten(name), "vendor")
