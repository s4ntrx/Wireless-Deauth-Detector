from deauth_detector.config import DetectorConfig
from deauth_detector.detector import DeauthDetector
from deauth_detector.models import BeaconInfo, DeauthEvent, ReconnectEvent, Severity

from .factories import AP, CLIENT


def deauth(timestamp, **overrides):
    values = dict(timestamp=timestamp, source=AP, destination=CLIENT, bssid=AP, reason=7,
                  rssi=-45, sequence=101)
    values.update(overrides)
    return DeauthEvent(**values)


def beacon(timestamp, rssi=-45, sequence=100, pmf_required=False):
    return BeaconInfo(timestamp, AP, "LabNet", 6, rssi, sequence, True, pmf_required)


def feed(detector, items):
    alerts = []
    for item in items:
        alerts.extend(detector.process(item))
    return alerts


def test_single_deauth_is_log_only():
    detector = DeauthDetector()
    assert feed(detector, [deauth(1.0)]) == []


def test_flood_opens_warning_then_escalates_to_critical():
    detector = DeauthDetector()
    alerts = feed(detector, [deauth(i * 0.05) for i in range(120)])
    kinds = [(alert.kind, alert.severity) for alert in alerts]
    assert kinds[0] == ("incident_opened", Severity.WARNING)
    assert ("incident_escalated", Severity.CRITICAL) in kinds


def test_incident_closes_after_quiet_period():
    detector = DeauthDetector()
    feed(detector, [deauth(i * 0.1) for i in range(15)])
    closing = detector.tick(100.0)
    assert [alert.kind for alert in closing] == ["incident_closed"]
    assert detector.closed_incidents[0].frames == 15


def test_repeated_client_targeting_triggers_without_flood():
    config = DetectorConfig(warning_frames=50, client_repeat_frames=5)
    alerts = feed(DeauthDetector(config), [deauth(i) for i in range(5)])
    assert alerts and "client_repeat" in alerts[0].incident["rules"]


def test_multiple_sources_against_one_client():
    sources = ["02:00:00:00:00:0%d" % i for i in range(1, 4)]
    events = [deauth(i * 0.1, source=source) for i, source in enumerate(sources)]
    alerts = feed(DeauthDetector(), events)
    assert alerts and "multi_source" in alerts[0].incident["rules"]


def test_rssi_mismatch_marks_spoofed_frames():
    detector = DeauthDetector()
    feed(detector, [beacon(0.0 + i * 0.1) for i in range(20)])
    alerts = feed(detector, [deauth(2.0 + i * 0.05, rssi=-20, sequence=100) for i in range(4)])
    assert alerts
    assert "rssi_mismatch" in alerts[0].incident["rules"]
    assert alerts[0].incident["attacker_estimate"]["mean_rssi_dbm"] == -20.0


def test_sequence_anomaly_detected():
    detector = DeauthDetector()
    feed(detector, [beacon(0.0, sequence=100)])
    alerts = feed(detector, [deauth(1.0 + i * 0.01, sequence=3000) for i in range(4)])
    assert alerts and "sequence_anomaly" in alerts[0].incident["rules"]


def test_genuine_ap_deauth_with_matching_fingerprint_is_not_flagged():
    detector = DeauthDetector()
    feed(detector, [beacon(0.0, rssi=-45, sequence=100)])
    assert feed(detector, [deauth(1.0, rssi=-46, sequence=104)]) == []


def test_pmf_violation_flagged_when_unprotected():
    detector = DeauthDetector()
    feed(detector, [beacon(0.0, pmf_required=True)])
    alerts = feed(detector, [deauth(1.0 + i * 0.01, protected=False) for i in range(3)])
    assert alerts and "pmf_violation" in alerts[0].incident["rules"]


def test_foreign_source_flagged_for_known_ap():
    detector = DeauthDetector()
    feed(detector, [beacon(0.0)])
    stranger = "02:11:22:33:44:55"
    alerts = feed(detector, [deauth(1.0 + i * 0.01, source=stranger) for i in range(3)])
    assert alerts and "foreign_source" in alerts[0].incident["rules"]


def test_known_ap_filter_ignores_other_networks():
    config = DetectorConfig(known_aps=frozenset({"00:11:22:33:44:55"}))
    detector = DeauthDetector(config)
    assert feed(detector, [deauth(i * 0.01) for i in range(50)]) == []


def test_reconnect_after_deauth_marks_victim():
    detector = DeauthDetector()
    feed(detector, [deauth(i) for i in range(4)])
    feed(detector, [ReconnectEvent(5.0, CLIENT, AP)])
    victims = detector.clients.victims()
    assert [(v.mac, v.deauths, v.reconnects) for v in victims] == [(CLIENT, 4, 1)]


def test_reconnect_without_prior_deauth_is_ignored():
    detector = DeauthDetector()
    feed(detector, [ReconnectEvent(5.0, CLIENT, AP)])
    assert detector.clients.victims(min_deauths=0, min_reconnects=0) == []
