from types import SimpleNamespace

from scapy.utils import wrpcap

from deauth_detector.cli import main

from .factories import sample_attack_capture


def test_analyze_then_timeline(tmp_path, capsys):
    pcap, log = tmp_path / "capture.pcap", tmp_path / "events.jsonl"
    wrpcap(str(pcap), sample_attack_capture())

    exit_code = main(["analyze", str(pcap), "--log", str(log), "--fail-on", "critical"])
    output = capsys.readouterr().out
    assert exit_code == 1
    assert "CRITICAL escalated" in output
    assert "ATTACK DETECTED" in output
    assert "Affected clients" in output

    assert main(["timeline", str(log)]) == 0
    timeline = capsys.readouterr().out
    assert "Incident #1" in timeline
    assert "rssi_mismatch" in timeline
    assert "Activity" in timeline
    assert "does not require protected management frames" in timeline
    assert "Next steps" in timeline


def test_benign_capture_is_clean(tmp_path, capsys):
    pcap = tmp_path / "quiet.pcap"
    wrpcap(str(pcap), [frame for frame in sample_attack_capture() if frame.haslayer("Dot11Beacon")])
    assert main(["analyze", str(pcap), "--fail-on", "warning"]) == 0
    assert "CLEAN" in capsys.readouterr().out


def test_unknown_config_key_is_rejected(tmp_path, capsys):
    config = tmp_path / "bad.toml"
    config.write_text("[detector]\nnot_a_setting = 1\n")
    assert main(["analyze", str(tmp_path / "missing.pcap"), "--config", str(config)]) == 2
    assert "unknown config keys" in capsys.readouterr().err


def test_no_command_prints_banner_and_help(capsys):
    assert main([]) == 0
    output = capsys.readouterr().out
    assert "s4ntrx" in output
    assert "analyze" in output and "monitor" in output


def test_reused_log_keeps_runs_separate(tmp_path, capsys, monkeypatch):
    pcap, log = tmp_path / "capture.pcap", tmp_path / "events.jsonl"
    wrpcap(str(pcap), sample_attack_capture())
    run_ids = iter(["20261008-100000", "20261008-110000"])
    monkeypatch.setattr("deauth_detector.alerts.time", SimpleNamespace(strftime=lambda *_: next(run_ids)))

    main(["analyze", str(pcap), "--log", str(log)])
    main(["analyze", str(pcap), "--log", str(log)])
    capsys.readouterr()
    main(["timeline", str(log)])
    output = capsys.readouterr().out
    assert output.count("Incident #1") == 2
    assert "20261008-100000" in output and "20261008-110000" in output
