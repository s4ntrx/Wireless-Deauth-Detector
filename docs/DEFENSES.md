# Responding to deauthentication attacks

Detection tells you an attack is happening. These changes make it ineffective.

1. Enable protected management frames (802.11w). Set PMF to required where every client supports it, optional otherwise. Clients ignore unprotected deauth and disassoc frames from a PMF-enabled AP. The timeline output notes when an AP does not require it.
2. Move to WPA3-Personal or WPA3-Enterprise. PMF is mandatory in WPA3.
3. Keep legacy 2.4 GHz and 5 GHz networks that do not support PMF on a separate SSID with no sensitive access.
4. Change channel only as a stopgap. Attackers follow the channel, so this buys minutes, not safety.
5. Locate the source. Combine detector alerts from several sensors; the RSSI estimate from one sensor is not enough.
6. Preserve evidence. The JSONL log is append-only and contains every deauth frame with timestamp, RSSI, sequence number, and protection flag.

## Escalation guide

| Alert | Suggested action |
| --- | --- |
| WARNING opened | check whether a legitimate roaming or AP restart event explains it |
| CRITICAL escalated, no spoof rules | likely a high-rate unspoofed flood; check for a misbehaving device or tool on site |
| CRITICAL with spoof rules | treat as an active attack; enable PMF, collect the log, notify incident response |
