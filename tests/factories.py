from scapy.layers.dot11 import (
    Dot11,
    Dot11Auth,
    Dot11Beacon,
    Dot11Deauth,
    Dot11Elt,
    RadioTap,
)

AP = "24:5a:4c:00:00:01"
CLIENT = "3c:22:fb:00:00:01"


def _stamp(frame, timestamp):
    rebuilt = RadioTap(bytes(frame))
    rebuilt.time = timestamp
    return rebuilt


def beacon_frame(timestamp, bssid=AP, ssid="LabNet", channel=6, rssi=-45, sequence=100, pmf_required=False):
    capabilities = 0xC0 if pmf_required else 0x80
    rsn = (
        b"\x01\x00" + b"\x00\x0f\xac\x04" + b"\x01\x00" + b"\x00\x0f\xac\x04"
        + b"\x01\x00" + b"\x00\x0f\xac\x02" + bytes([capabilities, 0x00])
    )
    frame = (
        RadioTap(present="dBm_AntSignal", dBm_AntSignal=rssi)
        / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid, SC=sequence << 4)
        / Dot11Beacon()
        / Dot11Elt(ID=0, info=ssid.encode())
        / Dot11Elt(ID=3, info=bytes([channel]))
        / Dot11Elt(ID=48, info=rsn)
    )
    return _stamp(frame, timestamp)


def deauth_frame(timestamp, source=AP, destination=CLIENT, bssid=AP, reason=7, rssi=-45, sequence=101):
    frame = (
        RadioTap(present="dBm_AntSignal", dBm_AntSignal=rssi)
        / Dot11(type=0, subtype=12, addr1=destination, addr2=source, addr3=bssid, SC=sequence << 4)
        / Dot11Deauth(reason=reason)
    )
    return _stamp(frame, timestamp)


def auth_frame(timestamp, client=CLIENT, bssid=AP):
    frame = (
        RadioTap()
        / Dot11(type=0, subtype=11, addr1=bssid, addr2=client, addr3=bssid)
        / Dot11Auth(seqnum=1)
    )
    return _stamp(frame, timestamp)


def sample_attack_capture(base=1_760_000_000.0):
    second_client = "14:18:77:aa:bb:02"
    frames = []
    sequence = 0
    for tick in range(200):
        sequence = (sequence + 3) % 4096
        frames.append(beacon_frame(base + tick * 0.1, rssi=-45, sequence=sequence))
    frames.append(deauth_frame(base + 3.0, rssi=-45, sequence=sequence, reason=3))
    for index in range(400):
        target = CLIENT if index % 2 else second_client
        frames.append(deauth_frame(base + 5.0 + index * 0.025, destination=target, reason=7,
                                   rssi=-25, sequence=(index * 37 + 2000) % 4096))
    frames.append(auth_frame(base + 16.0, client=CLIENT))
    frames.append(auth_frame(base + 16.5, client=second_client))
    return sorted(frames, key=lambda frame: float(frame.time))
