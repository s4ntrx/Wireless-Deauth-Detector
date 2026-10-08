from __future__ import annotations

import argparse
import os
import signal
import sys
import threading
import time
from collections.abc import Sequence

from rich.live import Live

from . import __version__
from .alerts import JsonlLog, WebhookSink, record_from
from .capture import ChannelHopper, read_pcap, set_channel, start_live_capture
from .config import DetectorConfig, load_config
from .detector import DeauthDetector
from .models import Alert, Severity
from .stats import CaptureStats
from .timeline import build_timelines, load_records
from .ui import (
    Dashboard,
    console,
    error_console,
    print_alert,
    render_banner,
    render_summary,
    render_timelines,
    render_vendor_table,
)

TICK_SECONDS = 1.0
ANALYZE_PROGRESS_STEP = 2000
FAIL_LEVELS = {"none": None, "warning": Severity.WARNING, "critical": Severity.CRITICAL}


class Pipeline:
    def __init__(self, config: DetectorConfig, log_path: str | None, webhook_url: str | None):
        self.log = JsonlLog(log_path) if log_path else None
        self.webhook = WebhookSink(webhook_url) if webhook_url else None
        self.stats = CaptureStats()
        self.detector = DeauthDetector(config, observer=self._record)
        self._lock = threading.Lock()

    def _record(self, item) -> None:
        if self.log:
            self.log.write(record_from(item))

    def handle(self, observation) -> None:
        if observation is None:
            return
        with self._lock:
            self.stats.observe(observation)
            self._emit(self.detector.process(observation))

    def tick(self) -> None:
        with self._lock:
            self._emit(self.detector.tick(time.time()))

    def finish(self) -> None:
        with self._lock:
            self._emit(self.detector.finalize())
        if self.log:
            self.log.close()

    def _emit(self, alerts: list[Alert]) -> None:
        for alert in alerts:
            self.stats.last_alert_summary = alert.summary
            if self.log:
                self.log.write(record_from(alert))
            print_alert(alert)
            if self.webhook:
                self.webhook(alert)


def build_config(args: argparse.Namespace) -> DetectorConfig:
    config = load_config(args.config) if args.config else DetectorConfig()
    if args.known_ap:
        known = frozenset(config.known_aps | {mac.lower() for mac in args.known_ap})
        config = DetectorConfig(**{**config.__dict__, "known_aps": known})
    return config


def exceeds_threshold(pipeline: Pipeline, fail_on: str) -> bool:
    threshold = FAIL_LEVELS[fail_on]
    return threshold is not None and any(i.severity >= threshold for i in pipeline.detector.closed_incidents)


def run_analyze(args: argparse.Namespace) -> int:
    pipeline = Pipeline(build_config(args), args.log, args.webhook)
    with console.status("[brand]Analyzing capture[/]") as status:
        for index, observation in enumerate(read_pcap(args.pcap), start=1):
            pipeline.handle(observation)
            if index % ANALYZE_PROGRESS_STEP == 0:
                status.update(f"[brand]Analyzing capture[/]  {index:,} frames")
    pipeline.finish()
    console.print(render_summary(pipeline.detector, pipeline.stats))
    return 1 if exceeds_threshold(pipeline, args.fail_on) else 0


def run_monitor(args: argparse.Namespace) -> int:
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        error_console.print("[crit]error:[/] monitor mode capture requires root privileges")
        return 2

    pipeline = Pipeline(build_config(args), args.log, args.webhook)
    channel_label = "unchanged"
    if args.channel:
        if not set_channel(args.interface, args.channel):
            error_console.print(f"[crit]error:[/] could not set channel {args.channel} on {args.interface}")
            return 2
        channel_label = f"locked to {args.channel}"

    hopper = None
    if args.hop:
        hopper = ChannelHopper(args.interface, dwell_seconds=args.dwell)
        hopper.start()
        channel_label = f"hopping 2.4 GHz ({args.dwell}s dwell)"

    stop = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    signal.signal(signal.SIGTERM, lambda *_: stop.set())

    dashboard = Dashboard(args.interface, channel_label, pipeline.detector, pipeline.stats)
    sniffer = start_live_capture(args.interface, pipeline.handle)
    console.print("[muted]Press Ctrl+C to stop and print the summary.[/]")
    try:
        with Live(dashboard, console=console, refresh_per_second=4):
            while not stop.wait(TICK_SECONDS):
                pipeline.tick()
    finally:
        sniffer.stop()
        if hopper:
            hopper.stop_event.set()
        pipeline.finish()
    console.print(render_summary(pipeline.detector, pipeline.stats))
    return 0


def run_timeline(args: argparse.Namespace) -> int:
    records = list(load_records(args.log))
    console.print(render_timelines(build_timelines(records, args.bssid.lower() if args.bssid else None)))
    return 0


def run_vendor(args: argparse.Namespace) -> int:
    console.print(render_vendor_table(args.addresses))
    return 0


def add_detection_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--config", help="path to a TOML config file")
    parser.add_argument("--known-ap", action="append", metavar="BSSID",
                        help="only monitor this BSSID (repeatable)")
    parser.add_argument("--log", metavar="FILE", help="append all events and alerts to a JSONL file")
    parser.add_argument("--webhook", metavar="URL", help="POST each alert as JSON to this URL")


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--no-banner", action="store_true", help="do not print the banner")

    parser = argparse.ArgumentParser(prog="deauth-detector", description="Detect 802.11 deauthentication attacks.",
                                     parents=[common])
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command")

    monitor = commands.add_parser("monitor", parents=[common], help="live capture from a monitor-mode interface")
    monitor.add_argument("-i", "--interface", required=True)
    monitor.add_argument("--channel", type=int, help="lock the interface to one channel")
    monitor.add_argument("--hop", action="store_true", help="hop across 2.4 GHz channels")
    monitor.add_argument("--dwell", type=float, default=0.4, help="seconds per channel when hopping")
    add_detection_options(monitor)
    monitor.set_defaults(handler=run_monitor)

    analyze = commands.add_parser("analyze", parents=[common], help="replay a pcap or pcapng capture")
    analyze.add_argument("pcap")
    analyze.add_argument("--fail-on", choices=sorted(FAIL_LEVELS), default="none",
                         help="exit with status 1 if an incident reaches this severity")
    add_detection_options(analyze)
    analyze.set_defaults(handler=run_analyze)

    timeline = commands.add_parser("timeline", parents=[common], help="render a forensic timeline from a JSONL log")
    timeline.add_argument("log")
    timeline.add_argument("--bssid")
    timeline.set_defaults(handler=run_timeline)

    vendor = commands.add_parser("vendor", parents=[common], help="look up the organization behind MAC addresses")
    vendor.add_argument("addresses", nargs="+", metavar="MAC")
    vendor.set_defaults(handler=run_vendor)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    show_banner = console.is_terminal and not args.no_banner

    if args.command is None:
        console.print(render_banner())
        parser.print_help()
        return 0
    if show_banner:
        console.print(render_banner())
    try:
        return args.handler(args)
    except (OSError, ValueError) as error:
        error_console.print(f"[crit]error:[/] {error}", markup=True, highlight=False)
        return 2
