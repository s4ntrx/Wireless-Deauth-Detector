from deauth_detector.cli import main
from deauth_detector.config import DetectorConfig
from deauth_detector.detector import DeauthDetector
from deauth_detector.vendors import lookup_vendor

from .test_detector import deauth, feed


def test_registered_vendor_is_resolved():
    info = lookup_vendor("14:18:77:aa:bb:cc")
    assert info.kind == "vendor"
    assert info.label.startswith("Dell")
    assert lookup_vendor("3C-22-FB-00-00-01").label.startswith("Apple")


def test_special_addresses_are_not_looked_up():
    assert lookup_vendor("ff:ff:ff:ff:ff:ff").kind == "broadcast"
    assert lookup_vendor("01:00:5e:00:00:01").kind == "multicast"
    assert lookup_vendor("de:ad:be:ef:00:01").kind == "local"
    assert lookup_vendor("not-a-mac").kind == "invalid"


def test_unregistered_prefix_is_reported_unknown():
    info = lookup_vendor("04:00:00:00:00:01")
    assert (info.kind, info.label) == ("unknown", "Unknown vendor")


def test_virtual_interface_resolves_base_vendor_only_when_asked():
    virtual_mac = "16:18:77:aa:bb:cc"
    assert lookup_vendor(virtual_mac).kind == "local"
    info = lookup_vendor(virtual_mac, virtual_interface=True)
    assert info.kind == "virtual" and "Dell" in info.label


def test_incident_details_carry_vendor_labels():
    dell_client = "14:18:77:aa:bb:cc"
    detector = DeauthDetector(DetectorConfig(warning_frames=3))
    alerts = feed(detector, [deauth(i * 0.05, destination=dell_client) for i in range(4)])
    vendors = alerts[0].incident["vendors"]
    assert vendors[dell_client].startswith("Dell")


def test_vendor_command(capsys):
    assert main(["vendor", "14:18:77:aa:bb:cc", "de:ad:be:ef:00:01"]) == 0
    output = capsys.readouterr().out
    assert "Dell" in output and "locally administered" in output


def test_vendor_command_hints_base_vendor_for_virtual_addresses(capsys):
    main(["vendor", "16:18:77:aa:bb:cc"])
    output = capsys.readouterr().out
    assert "possible base" in output and "Dell Inc." in output
