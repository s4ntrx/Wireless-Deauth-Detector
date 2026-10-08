from deauth_detector.capture import frequency_to_channel, parse_frame
from deauth_detector.models import BeaconInfo, DeauthEvent, ReconnectEvent

from .factories import AP, CLIENT, auth_frame, beacon_frame, deauth_frame


def test_parse_deauth_extracts_fields():
    event = parse_frame(deauth_frame(100.0, reason=2, rssi=-61, sequence=77))
    assert isinstance(event, DeauthEvent)
    assert (event.source, event.destination, event.bssid) == (AP, CLIENT, AP)
    assert (event.reason, event.rssi, event.sequence) == (2, -61, 77)
    assert event.client == CLIENT


def test_parse_beacon_reads_pmf_and_channel():
    beacon = parse_frame(beacon_frame(100.0, channel=11, pmf_required=True))
    assert isinstance(beacon, BeaconInfo)
    assert (beacon.ssid, beacon.channel) == ("LabNet", 11)
    assert beacon.pmf_capable and beacon.pmf_required


def test_parse_beacon_without_pmf_requirement():
    beacon = parse_frame(beacon_frame(100.0, pmf_required=False))
    assert beacon.pmf_capable and not beacon.pmf_required


def test_parse_auth_is_reconnect():
    assert isinstance(parse_frame(auth_frame(100.0)), ReconnectEvent)


def test_frequency_to_channel():
    assert frequency_to_channel(2437) == 6
    assert frequency_to_channel(5180) == 36
    assert frequency_to_channel(None) is None
