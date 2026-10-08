from __future__ import annotations

import itertools
import subprocess
import threading
from collections.abc import Callable, Iterator
from pathlib import Path

from scapy.layers.dot11 import (
    Dot11,
    Dot11Auth,
    Dot11AssoReq,
    Dot11Beacon,
    Dot11Deauth,
    Dot11Disas,
    Dot11Elt,
    Dot11ProbeResp,
    Dot11ReassoReq,
    RadioTap,
)
from scapy.sendrecv import AsyncSniffer
from scapy.utils import PcapReader

from .models import BeaconInfo, DeauthEvent, ReconnectEvent

Observation = DeauthEvent | BeaconInfo | ReconnectEvent

SSID_ELEMENT = 0
DS_PARAMETER_ELEMENT = 3
RSN_ELEMENT = 48
PROTECTED_FLAG = 0x40
PMF_REQUIRED_BIT = 0x40
PMF_CAPABLE_BIT = 0x80
CHANNELS_24GHZ = (1, 6, 11, 2, 7, 3, 8, 4, 9, 5, 10, 12, 13)


def frequency_to_channel(megahertz: int | None) -> int | None:
    if megahertz is None:
        return None
    if megahertz == 2484:
        return 14
    if 2412 <= megahertz <= 2472:
        return (megahertz - 2407) // 5
    if 5000 <= megahertz <= 5900:
        return (megahertz - 5000) // 5
    if 5955 <= megahertz <= 7115:
        return (megahertz - 5950) // 5
    return None


def parse_rsn_pmf(info: bytes) -> tuple[bool, bool]:
    try:
        offset = 6
        pairwise_count = int.from_bytes(info[offset : offset + 2], "little")
        offset += 2 + 4 * pairwise_count
        akm_count = int.from_bytes(info[offset : offset + 2], "little")
        offset += 2 + 4 * akm_count
        if len(info) < offset + 2:
            return False, False
        capabilities = info[offset]
    except (IndexError, ValueError):
        return False, False
    return bool(capabilities & PMF_CAPABLE_BIT), bool(capabilities & PMF_REQUIRED_BIT)


def _radio_metadata(packet) -> tuple[int | None, int | None]:
    radiotap = packet.getlayer(RadioTap)
    if radiotap is None:
        return None, None
    rssi = getattr(radiotap, "dBm_AntSignal", None)
    channel = frequency_to_channel(getattr(radiotap, "ChannelFrequency", None))
    return rssi, channel


def _parse_beacon(packet, dot11, timestamp, rssi, radio_channel) -> BeaconInfo:
    ssid, channel = "", radio_channel
    pmf_capable = pmf_required = False
    element = packet.getlayer(Dot11Elt)
    while element is not None and isinstance(element, Dot11Elt):
        if element.ID == SSID_ELEMENT:
            ssid = element.info.decode("utf-8", errors="replace")
        elif element.ID == DS_PARAMETER_ELEMENT and element.info:
            channel = element.info[0]
        elif element.ID == RSN_ELEMENT:
            pmf_capable, pmf_required = parse_rsn_pmf(bytes(element.info))
        element = element.payload.getlayer(Dot11Elt)
    return BeaconInfo(
        timestamp=timestamp,
        bssid=dot11.addr3.lower(),
        ssid=ssid,
        channel=channel,
        rssi=rssi,
        sequence=dot11.SC >> 4,
        pmf_capable=pmf_capable,
        pmf_required=pmf_required,
    )


def parse_frame(packet) -> Observation | None:
    dot11 = packet.getlayer(Dot11)
    if dot11 is None:
        return None
    timestamp = float(packet.time)
    rssi, channel = _radio_metadata(packet)

    removal = packet.getlayer(Dot11Deauth)
    kind = "deauth"
    if removal is None:
        removal = packet.getlayer(Dot11Disas)
        kind = "disassoc"
    if removal is not None:
        if not (dot11.addr1 and dot11.addr2 and dot11.addr3):
            return None
        return DeauthEvent(
            timestamp=timestamp,
            source=dot11.addr2.lower(),
            destination=dot11.addr1.lower(),
            bssid=dot11.addr3.lower(),
            reason=int(removal.reason),
            kind=kind,
            rssi=rssi,
            channel=channel,
            sequence=dot11.SC >> 4,
            protected=bool(int(dot11.FCfield) & PROTECTED_FLAG),
        )

    if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
        if not dot11.addr3:
            return None
        return _parse_beacon(packet, dot11, timestamp, rssi, channel)

    is_auth_start = packet.haslayer(Dot11Auth) and packet[Dot11Auth].seqnum == 1
    if is_auth_start or packet.haslayer(Dot11AssoReq) or packet.haslayer(Dot11ReassoReq):
        if dot11.addr2 and dot11.addr3:
            return ReconnectEvent(timestamp, dot11.addr2.lower(), dot11.addr3.lower())
    return None


def read_pcap(path: str | Path) -> Iterator[Observation]:
    with PcapReader(str(path)) as reader:
        for packet in reader:
            observation = parse_frame(packet)
            if observation is not None:
                yield observation


class ChannelHopper(threading.Thread):
    def __init__(self, interface: str, channels=CHANNELS_24GHZ, dwell_seconds: float = 0.4):
        super().__init__(daemon=True)
        self.interface = interface
        self.channels = channels
        self.dwell_seconds = dwell_seconds
        self.stop_event = threading.Event()

    def run(self) -> None:
        for channel in itertools.cycle(self.channels):
            if self.stop_event.is_set():
                return
            set_channel(self.interface, channel)
            self.stop_event.wait(self.dwell_seconds)


def set_channel(interface: str, channel: int) -> bool:
    result = subprocess.run(
        ["iw", "dev", interface, "set", "channel", str(channel)],
        capture_output=True,
        check=False,
    )
    return result.returncode == 0


def start_live_capture(interface: str, handler: Callable[[Observation], None]) -> AsyncSniffer:
    sniffer = AsyncSniffer(
        iface=interface,
        store=False,
        prn=lambda packet: handler(parse_frame(packet)),
    )
    sniffer.start()
    return sniffer
