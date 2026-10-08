from __future__ import annotations

import time
from typing import Any

from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

from . import __version__
from .detector import DeauthDetector
from .models import REASON_NAMES, Alert, Severity
from .stats import CaptureStats
from .timeline import IncidentTimeline
from .vendors import lookup_vendor

CYAN, GREEN, AMBER, RED = "#22d3ee", "#4ade80", "#fbbf24", "#f87171"
SLATE, SNOW, INK = "#94a3b8", "#e2e8f0", "#0f172a"

THEME = Theme(
    {
        "brand": f"bold {CYAN}",
        "ok": f"bold {GREEN}",
        "warn": f"bold {AMBER}",
        "crit": f"bold {RED}",
        "info": CYAN,
        "muted": SLATE,
        "label": f"bold {SLATE}",
        "value": SNOW,
        "vendor": f"italic {GREEN}",
    }
)

console = Console(theme=THEME, highlight=False)
error_console = Console(theme=THEME, stderr=True, highlight=False)

BANNER_ART = r"""
         __ __        __
   _____/ // / ____  / /_______  __
  / ___/ // /_/ __ \/ __/ ___/ |/_/
 (__  )__  __/ / / / /_/ /  _>  <
/____/  /_/ /_/ /_/\__/_/  /_/|_|
""".strip("\n").splitlines()

SEVERITY_STYLE = {Severity.INFO: "info", Severity.WARNING: "warn", Severity.CRITICAL: "crit"}
SEVERITY_COLOR = {Severity.INFO: CYAN, Severity.WARNING: AMBER, Severity.CRITICAL: RED}
SEVERITY_BY_NAME = {severity.name: severity for severity in Severity}

HEADLINES = {
    "incident_opened": "Attack pattern detected",
    "incident_escalated": "Attack escalated",
    "incident_closed": "Incident closed",
}

RULE_MEANING = {
    "flood": "frame rate against this access point is far above normal",
    "client_repeat": "the same client keeps getting disconnected",
    "multi_source": "several different MAC addresses are kicking one client",
    "foreign_source": "frames claim this AP but come from a third device",
    "rssi_mismatch": "signal strength differs from the real AP's beacons",
    "sequence_anomaly": "sequence numbers do not follow the real AP's",
    "pmf_violation": "unprotected frames sent to an AP that requires protection",
    "suspicious_reason": "reason code is common in attack tools",
}
FORGERY_RULES = {"foreign_source", "rssi_mismatch", "sequence_anomaly", "pmf_violation"}


def _blend(start: tuple[int, int, int], end: tuple[int, int, int], ratio: float) -> str:
    channels = (round(a + (b - a) * ratio) for a, b in zip(start, end))
    return "#{:02x}{:02x}{:02x}".format(*channels)


def _hex_to_rgb(color: str) -> tuple[int, int, int]:
    return int(color[1:3], 16), int(color[3:5], 16), int(color[5:7], 16)


def render_banner() -> Group:
    last_line = max(len(BANNER_ART) - 1, 1)
    art = [
        Text(line, style=f"bold {_blend(_hex_to_rgb(CYAN), _hex_to_rgb(GREEN), index / last_line)}")
        for index, line in enumerate(BANNER_ART)
    ]
    title = Text.assemble(("DEAUTH DETECTOR", "bold white"), (f"   v{__version__}", "muted"))
    subtitle = Text("Passive 802.11 deauthentication monitor", style="muted")
    credit = Text.assemble(("github.com/", "muted"), ("s4ntrx", "brand"))
    return Group(*art, Text(), title, subtitle, credit, Rule(style="muted"))


def format_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes, remainder = divmod(int(seconds), 60)
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h{minutes:02d}m{remainder:02d}s" if hours else f"{minutes}m{remainder:02d}s"


def _clock(timestamp: float) -> str:
    return time.strftime("%H:%M:%S", time.localtime(timestamp))


def _stamp(timestamp: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))


def _fields() -> Table:
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="label", no_wrap=True)
    grid.add_column(style="value", overflow="fold")
    return grid


def _stack(lines: list[Text]) -> Group:
    return Group(*lines)


def _badge(severity: Severity) -> Text:
    return Text(f" {severity.name} ", style=f"bold {INK} on {SEVERITY_COLOR[severity]}")


def _access_point(details: dict[str, Any]) -> Text:
    text = Text(details["bssid"], style="value")
    if details.get("ssid"):
        text.append(f"  {details['ssid']}", style="brand")
    vendor = details.get("vendors", {}).get(details["bssid"])
    if vendor:
        text.append(f"  {vendor}", style="vendor")
    if details.get("channel"):
        text.append(f"  channel {details['channel']}", style="muted")
    return text


def _evidence(rules: list[str]) -> Group:
    if not rules:
        return Group(Text("pending", style="muted"))
    return _stack(
        [
            Text.assemble((rule, "bold"), ("  " + RULE_MEANING.get(rule, ""), "muted"))
            for rule in rules
        ]
    )


def _device_lines(entries: list[list], vendors: dict[str, str]) -> Group:
    if not entries:
        return Group(Text("none", style="muted"))
    return _stack(
        [
            Text.assemble(
                (mac, "value"),
                (f"  {vendors.get(mac) or lookup_vendor(mac).label}", "vendor"),
                (f"  x{count}", "muted"),
            )
            for mac, count in entries
        ]
    )


def _attacker_line(estimate: dict[str, Any]) -> str:
    return (
        f"mean signal {estimate['mean_rssi_dbm']} dBm, roughly {estimate['approx_distance_m']} m "
        "away (single sensor, coarse)"
    )


def advice_for(details: dict[str, Any]) -> list[str]:
    rules = set(details["rules"])
    steps = []
    if rules & FORGERY_RULES:
        steps.append("Frames look forged, not sent by your AP. Treat this as an active attack.")
    elif details["severity"] == "CRITICAL":
        steps.append("High-rate flood without forgery signs. Look for a faulty device or a tool nearby.")
    else:
        steps.append("Rule out roaming or an AP restart before escalating.")
    if details.get("pmf_required") is False:
        steps.append("Enable PMF (802.11w) on this AP. WPA3 requires it.")
    if details["severity"] == "CRITICAL":
        steps.append("Keep the JSONL log as evidence and notify whoever owns incident response.")
    return steps


def _next_steps(details: dict[str, Any]) -> Group:
    return _stack([Text(f"- {step}") for step in advice_for(details)])


def alert_panel(alert: Alert) -> Panel:
    details = alert.incident
    style = SEVERITY_STYLE[alert.severity]
    volume = (
        f"{details['frames']} frames   {len(details['clients'])} clients   "
        f"{details['spoofed_frames']} spoof-flagged   peak {details['peak_window_frames']} per window"
    )
    if alert.kind == "incident_closed":
        volume += f"   lasted {format_duration(details['duration_seconds'])}"

    grid = _fields()
    grid.add_row("Access point", _access_point(details))
    grid.add_row("Evidence", _evidence(details["rules"]))
    grid.add_row("Volume", volume)
    grid.add_row("Targets", _device_lines(details["clients"][:3], details.get("vendors", {})))
    if details.get("attacker_estimate"):
        grid.add_row("Transmitter", _attacker_line(details["attacker_estimate"]))
    grid.add_row("Next steps", _next_steps(details))

    title = Text.assemble(_badge(alert.severity), (f" {HEADLINES[alert.kind]}  #{details['incident_id']} ", style))
    return Panel(
        grid,
        title=title,
        title_align="left",
        subtitle=Text(_stamp(alert.timestamp), style="muted"),
        subtitle_align="right",
        border_style=style,
        box=box.ROUNDED,
        padding=(1, 2),
    )


def alert_line(alert: Alert) -> str:
    return f"[{_stamp(alert.timestamp)}] {alert.summary}"


def print_alert(alert: Alert) -> None:
    if console.is_terminal:
        console.print(alert_panel(alert))
    else:
        console.print(alert_line(alert), markup=False, soft_wrap=True)


class Dashboard:
    def __init__(self, interface: str, channel_label: str, detector: DeauthDetector, stats: CaptureStats):
        self.interface = interface
        self.channel_label = channel_label
        self.detector = detector
        self.stats = stats

    def __rich__(self) -> Panel:
        active = self.detector.open_incidents
        if active:
            plural = "s" if len(active) > 1 else ""
            status = Text(f"UNDER ATTACK   {len(active)} active incident{plural}", style="crit")
            border = "crit"
        else:
            status = Text("MONITORING   no active incidents", style="ok")
            border = "ok"

        grid = Table.grid(padding=(0, 3))
        for column_style in ("label", "value", "label", "value"):
            grid.add_column(style=column_style, no_wrap=True)
        stats = self.stats
        grid.add_row("Interface", self.interface, "Deauth frames", f"{stats.deauths:,}")
        grid.add_row("Channel", self.channel_label, "Deauth rate", f"{stats.deauth_rate():.1f} per second")
        grid.add_row("Uptime", format_duration(stats.elapsed_seconds), "Beacons", f"{stats.beacons:,}")
        grid.add_row("APs tracked", str(len(self.detector.access_points)), "Reconnects", f"{stats.reconnects:,}")

        last_alert = Text(stats.last_alert_summary or "no alerts yet", style="muted", overflow="ellipsis", no_wrap=True)
        return Panel(
            Group(status, Text(), grid, Text(), last_alert),
            title=Text(" s4ntrx | deauth-detector live ", style="brand"),
            title_align="left",
            border_style=border,
            box=box.ROUNDED,
            padding=(1, 2),
        )


def render_summary(detector: DeauthDetector, stats: CaptureStats) -> Group:
    incidents = detector.closed_incidents
    counts = {severity: sum(1 for item in incidents if item.severity == severity) for severity in Severity}

    if incidents:
        headline = Text("ATTACK DETECTED", style="crit")
        detail = f"   {len(incidents)} incident(s): {counts[Severity.CRITICAL]} critical, {counts[Severity.WARNING]} warning"
        border = "crit"
    else:
        headline = Text("CLEAN", style="ok")
        detail = "   no deauthentication attack patterns found"
        border = "ok"

    facts = (
        f"{stats.deauths:,} deauth/disassoc frames   {stats.beacons:,} beacons   "
        f"{stats.reconnects:,} reconnects   capture span {format_duration(stats.capture_span_seconds)}"
    )
    parts: list[Any] = [
        Panel(
            Group(Text.assemble(headline, (detail, "value")), Text(facts, style="muted")),
            title=Text(" Result ", style=border),
            title_align="left",
            border_style=border,
            box=box.ROUNDED,
            padding=(0, 2),
        )
    ]

    if incidents:
        table = Table(box=box.SIMPLE_HEAD, header_style="label", pad_edge=False, expand=True)
        for name, justify in (("#", "right"), ("Severity", "left"), ("Access point", "left"),
                              ("Frames", "right"), ("Lasted", "right"), ("Evidence", "left")):
            table.add_column(name, justify=justify, no_wrap=name != "Evidence",
                             min_width=26 if name == "Evidence" else None)
        for incident in incidents:
            profile = detector.access_points.get(incident.bssid)
            access_point = Text(incident.bssid, style="value")
            if profile and profile.ssid:
                access_point.append(f"\n{profile.ssid}", style="brand")
            access_point.append(f"\n{lookup_vendor(incident.bssid, virtual_interface=True).label}", style="vendor")
            table.add_row(
                str(incident.incident_id),
                Text(incident.severity.name, style=SEVERITY_STYLE[incident.severity]),
                access_point,
                f"{incident.frames:,}",
                format_duration(incident.last_seen - incident.started),
                ", ".join(sorted(incident.rules)),
            )
        parts.append(table)

    victims = detector.clients.victims()
    if victims:
        table = Table(title="Affected clients (disconnected repeatedly, then reconnected)", title_style="label",
                      title_justify="left", box=box.SIMPLE_HEAD, header_style="label", pad_edge=False,
                      expand=True)
        table.add_column("Client")
        table.add_column("Vendor", style="vendor")
        table.add_column("Deauths", justify="right")
        table.add_column("Reconnects", justify="right")
        for profile in victims[:10]:
            table.add_row(profile.mac, lookup_vendor(profile.mac).label,
                          f"{profile.deauths:,}", f"{profile.reconnects:,}")
        parts.append(table)

    if incidents:
        worst = max(incidents, key=lambda item: item.severity)
        steps = advice_for(detector.describe(worst))
        parts.append(Panel(_stack([Text(f"- {step}") for step in steps]), title=Text(" Next steps ", style="label"),
                           title_align="left", border_style="muted", box=box.ROUNDED, padding=(0, 2)))
    return Group(*parts)


def _activity_chart(activity: list[tuple[float, int]]) -> Table:
    bar_character = "#" if console.options.ascii_only else "\u2588"
    peak = max((count for _, count in activity), default=1) or 1
    chart = Table.grid(padding=(0, 2))
    chart.add_column(style="muted", no_wrap=True)
    chart.add_column(no_wrap=True)
    chart.add_column(style="value", justify="right")
    for moment, count in activity:
        ratio = count / peak
        style = "crit" if ratio >= 0.66 else "warn" if ratio >= 0.33 else "info"
        width = max(1 if count else 0, round(36 * ratio))
        chart.add_row(_clock(moment), Text(bar_character * width, style=style), str(count))
    return chart


def timeline_panel(timeline: IncidentTimeline) -> Panel:
    final = timeline.final
    severity = SEVERITY_BY_NAME[final["severity"]]
    reasons = _stack(
        [
            Text(f"{code}  {REASON_NAMES.get(int(code), 'other')}  x{count}")
            for code, count in final["reasons"].items()
        ]
    )
    events = _stack(
        [
            Text.assemble(
                (_clock(item["timestamp"]), "muted"),
                ("  ", ""),
                (item["kind"].removeprefix("incident_").ljust(10), "bold"),
                (item["severity"], SEVERITY_STYLE[SEVERITY_BY_NAME[item["severity"]]]),
            )
            for item in timeline.history
        ]
    )

    grid = _fields()
    grid.add_row("Access point", _access_point(final))
    grid.add_row("Window", f"{_stamp(final['started'])}  to  {_clock(final['last_seen'])}   "
                           f"({format_duration(final['duration_seconds'])})")
    grid.add_row("Volume", f"{final['frames']} frames   peak {final['peak_window_frames']} per window   "
                           f"{final['spoofed_frames']} spoof-flagged")
    grid.add_row("Evidence", _evidence(final["rules"]))
    grid.add_row("Reason codes", reasons)
    grid.add_row("Clients", _device_lines(final["clients"], final.get("vendors", {})))
    grid.add_row("Sources", _device_lines(final["sources"], final.get("vendors", {})))
    if final.get("attacker_estimate"):
        grid.add_row("Transmitter", _attacker_line(final["attacker_estimate"]))
    if final.get("pmf_required") is False:
        grid.add_row("Exposure", Text("AP does not require protected management frames (PMF)", style="warn"))
    if timeline.reconnects:
        grid.add_row("Reconnects", f"{timeline.reconnects} client reconnect(s) during or after the attack")
    grid.add_row("Events", events)
    if timeline.activity:
        grid.add_row("Activity", _activity_chart(timeline.activity))
    grid.add_row("Next steps", _next_steps(final))

    title = Text.assemble(_badge(severity), (f" Incident #{final['incident_id']} ", SEVERITY_STYLE[severity]))
    subtitle = Text(f"run {timeline.run}", style="muted") if timeline.run else None
    return Panel(grid, title=title, title_align="left", subtitle=subtitle, subtitle_align="right",
                 border_style=SEVERITY_STYLE[severity], box=box.ROUNDED, padding=(1, 2))


def render_timelines(timelines: list[IncidentTimeline]) -> Group:
    if not timelines:
        return Group(Panel(Text("No incidents found in this log.", style="muted"), border_style="muted",
                           box=box.ROUNDED))
    return Group(*(timeline_panel(item) for item in timelines))


def render_vendor_table(addresses: list[str]) -> Table:
    table = Table(box=box.SIMPLE_HEAD, header_style="label", pad_edge=False)
    table.add_column("Address", style="value", no_wrap=True)
    table.add_column("Type", style="muted")
    table.add_column("Organization", style="vendor")
    kind_names = {
        "vendor": "registered", "virtual": "virtual interface", "local": "locally administered",
        "multicast": "multicast", "broadcast": "broadcast", "unknown": "unregistered", "invalid": "invalid",
    }
    for address in addresses:
        info = lookup_vendor(address)
        label = info.label
        if info.kind == "local":
            virtual = lookup_vendor(address, virtual_interface=True)
            if virtual.kind == "virtual":
                label = f"{info.label}, possible base prefix: {virtual.label.removesuffix(' (virtual interface)')}"
        table.add_row(address.lower(), kind_names[info.kind], label)
    return table
