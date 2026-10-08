from rich.console import Console

from deauth_detector.config import DetectorConfig
from deauth_detector.detector import DeauthDetector
from deauth_detector.stats import CaptureStats
from deauth_detector.ui import THEME, Dashboard, advice_for, alert_line, alert_panel, render_banner

from .test_detector import deauth, feed


def render(renderable, width=100):
    recorder = Console(theme=THEME, width=width, record=True, force_terminal=False)
    recorder.print(renderable)
    return recorder.export_text()


def first_alert():
    detector = DeauthDetector(DetectorConfig(warning_frames=3))
    return feed(detector, [deauth(i * 0.05) for i in range(4)])[0], detector


def test_banner_contains_github_name():
    text = render(render_banner())
    assert "github.com/s4ntrx" in text
    assert "DEAUTH DETECTOR" in text


def test_alert_panel_explains_rules_in_plain_language():
    alert, _ = first_alert()
    text = render(alert_panel(alert))
    assert "WARNING" in text
    assert "frame rate against this access point is far above normal" in text
    assert "Next steps" in text


def test_alert_line_is_grep_friendly():
    alert, _ = first_alert()
    line = alert_line(alert)
    assert "WARNING opened bssid=" in line and line.startswith("[")


def test_advice_distinguishes_forged_from_plain_flood():
    forged = advice_for({"rules": ["rssi_mismatch"], "severity": "CRITICAL", "pmf_required": True})
    plain = advice_for({"rules": ["flood"], "severity": "CRITICAL", "pmf_required": True})
    assert "forged" in forged[0]
    assert "forged" not in plain[0]


def test_dashboard_reports_attack_state():
    alert, detector = first_alert()
    dashboard = Dashboard("wlan1", "locked to 6", detector, CaptureStats())
    assert "UNDER ATTACK" in render(dashboard)
    detector.finalize()
    assert "MONITORING" in render(dashboard)
