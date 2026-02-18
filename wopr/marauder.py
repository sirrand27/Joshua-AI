"""
W.O.P.R. Network Defense Sentry — ESP32 Marauder RF Monitor
Serial interface to ESP32 Marauder via Flipper Zero USB-UART Bridge.

Provides RF-layer awareness: rogue AP detection, deauth attack monitoring,
probe request intelligence, and Pwnagotchi/war-driver detection.
Complements UniFi controller-level monitoring with over-the-air SIGINT.

Prerequisite: Flipper Zero in USB-UART Bridge mode (GPIO > USB-UART Bridge,
115200 baud, pins 13/14) with ESP32 Marauder GPIO board attached.

Mode cycling (4-phase):
  1. sniffdeauth  — primary passive monitoring (~80% of time)
  2. scanap       — AP discovery + rogue detection (every 5 min, 15s dwell)
  3. sniffprobe   — probe request intelligence (every 10 min, 30s dwell)
  4. sniffpwnagotchi — war-driver detection (every 15 min, 20s dwell)
"""

import logging
import os
import re
import threading
import time
from collections import defaultdict, deque

from config import (
    MARAUDER_DEVICE, MARAUDER_BAUD,
    MARAUDER_SCAN_INTERVAL, MARAUDER_SCAN_DWELL,
    MARAUDER_PROBE_INTERVAL, MARAUDER_PROBE_DWELL,
    MARAUDER_PWNAGOTCHI_INTERVAL, MARAUDER_PWNAGOTCHI_DWELL,
    MARAUDER_DEAUTH_BURST_THRESHOLD, MARAUDER_DEAUTH_BURST_WINDOW,
)

logger = logging.getLogger(__name__)

# ── Serial Output Parsers ─────────────────────────────────
# Matched to actual ESP32 Marauder output format (firmware v0.13+)

# scanap: "-38 Ch: 9 BSSID: 9c:05:d6:37:44:a4 ESSID: SlipStream2.4"
_RE_SCANAP = re.compile(
    r'(-?\d+)\s+Ch:\s*(\d+)\s+BSSID:\s*([0-9a-fA-F:]{17})\s+ESSID:\s*(.*)'
)
# sniffdeauth: "Deauth: AA:BB:CC:DD:EE:FF -> 11:22:33:44:55:66 Reason: N Type: N"
_RE_DEAUTH_V1 = re.compile(
    r'Deauth:\s*([0-9a-fA-F:]{17})\s*->\s*([0-9a-fA-F:]{17})'
)
# Alternate format: "Type: Deauth Src: AA:BB:CC:DD:EE:FF Dst: 11:22:33:44:55:66"
_RE_DEAUTH_V2 = re.compile(
    r'Src:\s*([0-9a-fA-F:]{17})\s+Dst:\s*([0-9a-fA-F:]{17})'
)
# sniffprobe: RSSI + BSSID + ESSID (same format as scanap but from probe frames)
# Also: "Src: AA:BB:CC:DD:EE:FF SSID: NetworkName" or RSSI-prefixed
_RE_PROBE_V1 = re.compile(
    r'(-?\d+)\s+Ch:\s*(\d+)\s+BSSID:\s*([0-9a-fA-F:]{17})\s+ESSID:\s*(.*)'
)
_RE_PROBE_V2 = re.compile(
    r'Src:\s*([0-9a-fA-F:]{17}).*?(?:SSID|ESSID):\s*(.*)'
)
# sniffpwnagotchi: "Pwnagotchi: <name> (AA:BB:CC:DD:EE:FF) RSSI: -NN"
# Also: name + MAC in various formats
_RE_PWNAGOTCHI = re.compile(
    r'([Pp]wnagotchi|[Pp]wnd?).*?([0-9a-fA-F:]{17})'
)
# Fallback: any line with "pwnagotchi" in it (case-insensitive)
_RE_PWNAGOTCHI_NAME = re.compile(r'name[:\s]*["\']?(\S+)', re.IGNORECASE)

# Status lines to ignore (not data)
_IGNORE_PREFIXES = (
    "Starting", "Stopping", "ESP32 Marauder", "By:", "---", "> ",
    "Beacon:", "Failed to set", "#",
)


class MarauderMonitor:
    """ESP32 Marauder serial interface via Flipper Zero USB-UART bridge.

    4-phase mode cycling for comprehensive RF-layer defense:
      sniffdeauth (primary) → scanap → sniffprobe → sniffpwnagotchi → repeat
    """

    def __init__(self, blackboard, voice):
        self.blackboard = blackboard
        self.voice = voice
        self._device_path = MARAUDER_DEVICE
        self._baud = MARAUDER_BAUD

        # Timing config
        self._scan_interval = MARAUDER_SCAN_INTERVAL
        self._scan_dwell = MARAUDER_SCAN_DWELL
        self._probe_interval = MARAUDER_PROBE_INTERVAL
        self._probe_dwell = MARAUDER_PROBE_DWELL
        self._pwnagotchi_interval = MARAUDER_PWNAGOTCHI_INTERVAL
        self._pwnagotchi_dwell = MARAUDER_PWNAGOTCHI_DWELL
        self._burst_threshold = MARAUDER_DEAUTH_BURST_THRESHOLD
        self._burst_window = MARAUDER_DEAUTH_BURST_WINDOW

        # Serial state
        self._fd = None
        self._reader_thread = None
        self._running = False
        self._current_mode = None
        self._mode_lock = threading.Lock()

        # Availability
        self._available = None  # None = unchecked, True/False after probe
        self._connect_attempted = False

        # AP scan data
        self._known_rf_aps = {}  # bssid -> {ssid, channel, rssi, first_seen, last_seen, count}
        self._ap_scan_buffer = []
        self._last_scan_time = 0

        # Deauth tracking
        self._deauth_events = deque(maxlen=1000)
        self._deauth_rate = defaultdict(list)  # src_mac -> [timestamps]
        self._deauth_total = 0

        # Probe request tracking
        self._probe_devices = {}  # src_mac -> {ssids: set, first_seen, last_seen, count}
        self._probe_buffer = []   # current sweep results
        self._last_probe_time = 0
        self._probe_total = 0

        # Pwnagotchi tracking
        self._pwnagotchi_detections = {}  # mac -> {name, rssi, first_seen, last_seen, count}
        self._pwnagotchi_buffer = []
        self._last_pwnagotchi_time = 0

        logger.info(
            f"MarauderMonitor initialized (device={self._device_path}, "
            f"ap_scan={self._scan_interval}s/{self._scan_dwell}s, "
            f"probe={self._probe_interval}s/{self._probe_dwell}s, "
            f"pwnagotchi={self._pwnagotchi_interval}s/{self._pwnagotchi_dwell}s)")

    # ── Serial Connection ──────────────────────────────────

    def connect(self):
        """Open serial connection to Marauder. Returns True on success."""
        try:
            import termios

            self._fd = os.open(self._device_path, os.O_RDWR | os.O_NOCTTY)

            # Configure termios for 115200 8N1 raw mode
            attrs = termios.tcgetattr(self._fd)

            attrs[0] = 0  # iflag: no parity, no strip, no flow control
            attrs[1] = 0  # oflag: raw
            attrs[2] = (termios.CS8 | termios.CREAD | termios.CLOCAL)  # 8N1
            attrs[3] = 0  # lflag: raw (no echo, no canonical, no signals)

            baud_const = getattr(termios, f'B{self._baud}', termios.B115200)
            attrs[4] = baud_const  # ispeed
            attrs[5] = baud_const  # ospeed

            attrs[6][termios.VMIN] = 1   # read at least 1 byte
            attrs[6][termios.VTIME] = 1  # 100ms timeout

            termios.tcsetattr(self._fd, termios.TCSANOW, attrs)
            termios.tcflush(self._fd, termios.TCIOFLUSH)

            self._available = True
            self._connect_attempted = True

            # Start background reader
            self._running = True
            self._reader_thread = threading.Thread(
                target=self._reader_loop, daemon=True, name="marauder-reader")
            self._reader_thread.start()

            # Start in sniffdeauth mode (primary passive monitoring)
            time.sleep(0.5)  # let serial settle
            self._send_command("stopscan")
            time.sleep(0.5)
            self._send_command("sniffdeauth")
            self._current_mode = "sniffdeauth"

            logger.info(f"Marauder connected on {self._device_path} @ {self._baud} baud — "
                        f"sniffdeauth active")
            return True

        except FileNotFoundError:
            logger.warning(f"Marauder device not found: {self._device_path} "
                           f"(Flipper not in USB-UART Bridge mode?)")
            self._available = False
            self._connect_attempted = True
            return False

        except PermissionError:
            logger.warning(f"Marauder permission denied: {self._device_path} "
                           f"(Docker device passthrough missing?)")
            self._available = False
            self._connect_attempted = True
            return False

        except Exception as e:
            logger.warning(f"Marauder connect failed: {e}")
            self._available = False
            self._connect_attempted = True
            return False

    def disconnect(self):
        """Close serial connection."""
        self._running = False
        if self._fd is not None:
            try:
                self._send_command("stopscan")
                time.sleep(0.3)
            except Exception:
                pass
            try:
                os.close(self._fd)
            except Exception:
                pass
            self._fd = None
        if self._reader_thread and self._reader_thread.is_alive():
            self._reader_thread.join(timeout=3)
        self._current_mode = None
        self._available = False

    def _send_command(self, cmd):
        """Send a command to Marauder over serial."""
        if self._fd is None:
            return
        try:
            os.write(self._fd, (cmd + '\n').encode('ascii'))
        except OSError as e:
            logger.warning(f"Marauder send failed: {e}")
            self._available = False

    # ── Background Reader ──────────────────────────────────

    def _reader_loop(self):
        """Background thread: reads serial output line-by-line, dispatches to parsers."""
        buf = b''
        while self._running and self._fd is not None:
            try:
                chunk = os.read(self._fd, 256)
                if not chunk:
                    continue
                buf += chunk

                # Process complete lines
                while b'\n' in buf:
                    line_bytes, buf = buf.split(b'\n', 1)
                    line = line_bytes.decode('ascii', errors='replace').strip()
                    if not line:
                        continue

                    # Skip status/banner lines
                    if any(line.startswith(p) for p in _IGNORE_PREFIXES):
                        continue

                    # Dispatch to parser based on current mode
                    mode = self._current_mode
                    if mode == 'scanap':
                        self._parse_scanap_line(line)
                    elif mode == 'sniffdeauth':
                        self._parse_deauth_line(line)
                    elif mode == 'sniffprobe':
                        self._parse_probe_line(line)
                    elif mode == 'sniffpwnagotchi':
                        self._parse_pwnagotchi_line(line)

            except OSError as e:
                if self._running:
                    logger.warning(f"Marauder serial read error: {e} — marking offline")
                    self._available = False
                break
            except Exception as e:
                if self._running:
                    logger.debug(f"Marauder reader exception: {e}")

        logger.info("Marauder reader thread exited")

    # ── Line Parsers ───────────────────────────────────────

    def _parse_scanap_line(self, line):
        """Parse scanap output: RSSI, channel, BSSID, ESSID."""
        m = _RE_SCANAP.search(line)
        if not m:
            return

        ap = {
            "ssid": m.group(4).strip(),
            "bssid": m.group(3).lower(),
            "channel": int(m.group(2)),
            "rssi": int(m.group(1)),
        }

        self._ap_scan_buffer.append(ap)

        # Update known AP tracking
        bssid = ap["bssid"]
        now = time.time()
        if bssid in self._known_rf_aps:
            existing = self._known_rf_aps[bssid]
            existing["last_seen"] = now
            existing["count"] += 1
            existing["rssi"] = ap["rssi"]
        else:
            self._known_rf_aps[bssid] = {
                "ssid": ap["ssid"],
                "channel": ap["channel"],
                "rssi": ap["rssi"],
                "first_seen": now,
                "last_seen": now,
                "count": 1,
            }

    def _parse_deauth_line(self, line):
        """Parse sniffdeauth output: source MAC, destination MAC."""
        m = _RE_DEAUTH_V1.search(line) or _RE_DEAUTH_V2.search(line)
        if not m:
            return

        now = time.time()
        src = m.group(1).lower()
        dst = m.group(2).lower()

        self._deauth_events.append((now, src, dst))
        self._deauth_rate[src].append(now)
        self._deauth_total += 1

    def _parse_probe_line(self, line):
        """Parse sniffprobe output: source MAC + probed SSID.

        Tracks per-device probe history to detect reconnaissance patterns.
        """
        src = None
        ssid = None

        # Try RSSI-prefixed format (same as scanap but from probe frames)
        m = _RE_PROBE_V1.search(line)
        if m:
            src = m.group(3).lower()
            ssid = m.group(4).strip()
        else:
            # Try Src: MAC SSID: name format
            m = _RE_PROBE_V2.search(line)
            if m:
                src = m.group(1).lower()
                ssid = m.group(2).strip()

        if not src:
            return

        now = time.time()
        self._probe_total += 1

        # Build per-device probe history
        if src not in self._probe_devices:
            self._probe_devices[src] = {
                "ssids": set(),
                "first_seen": now,
                "last_seen": now,
                "count": 0,
            }

        device = self._probe_devices[src]
        device["last_seen"] = now
        device["count"] += 1
        if ssid:
            device["ssids"].add(ssid)

        # Buffer for current sweep
        self._probe_buffer.append({"src": src, "ssid": ssid, "time": now})

    def _parse_pwnagotchi_line(self, line):
        """Parse sniffpwnagotchi output: detect Pwnagotchi beacon frames.

        Pwnagotchis broadcast custom beacon frames with identifiable patterns.
        Detection = someone nearby is actively hunting WPA handshakes.
        """
        mac = None
        name = "unknown"

        m = _RE_PWNAGOTCHI.search(line)
        if m:
            mac = m.group(2).lower()
            # Try to extract name
            nm = _RE_PWNAGOTCHI_NAME.search(line)
            if nm:
                name = nm.group(1).strip('"\'')
        elif "pwnagotchi" in line.lower() or "pwnd" in line.lower():
            # Fallback: any line mentioning pwnagotchi during sniffpwnagotchi mode
            # Try to find a MAC anywhere in the line
            mac_match = re.search(r'([0-9a-fA-F:]{17})', line)
            if mac_match:
                mac = mac_match.group(1).lower()
            nm = _RE_PWNAGOTCHI_NAME.search(line)
            if nm:
                name = nm.group(1).strip('"\'')

        if not mac:
            return

        now = time.time()
        self._pwnagotchi_buffer.append({"mac": mac, "name": name, "time": now})

        # Track persistent detections
        if mac in self._pwnagotchi_detections:
            existing = self._pwnagotchi_detections[mac]
            existing["last_seen"] = now
            existing["count"] += 1
        else:
            self._pwnagotchi_detections[mac] = {
                "name": name,
                "first_seen": now,
                "last_seen": now,
                "count": 1,
            }

    # ── Mode Switching ─────────────────────────────────────

    def _switch_mode(self, new_mode):
        """Switch Marauder to a new scan mode. Thread-safe."""
        with self._mode_lock:
            if self._fd is None or not self._available:
                return

            # Stop current scan
            self._send_command("stopscan")
            time.sleep(1.0)  # wait for "Stopping WiFi tran/recv"

            # Clear scan buffer
            self._ap_scan_buffer.clear()

            # Start new mode
            self._send_command(new_mode)
            self._current_mode = new_mode
            logger.debug(f"Marauder mode switched to: {new_mode}")

    # ── Poll Interface (called from defense loop) ──────────

    def poll(self, poll_count, managed_aps, known_ssids):
        """Run periodic checks with 4-phase mode cycling.

        Phase rotation (all times from last scan of each type):
          1. sniffdeauth  — primary (always returns to this)
          2. scanap       — every SCAN_INTERVAL (5 min), SCAN_DWELL (15s)
          3. sniffprobe   — every PROBE_INTERVAL (10 min), PROBE_DWELL (30s)
          4. sniffpwnagotchi — every PWNAGOTCHI_INTERVAL (15 min), PWNAGOTCHI_DWELL (20s)

        Returns list of anomaly dicts with 'type', 'source'='marauder'.
        """
        # Connect on first call
        if not self._connect_attempted:
            if not self.connect():
                return []

        if not self._available:
            # Retry connection every 100 cycles (~50 min)
            if poll_count % 100 == 0 and poll_count > 0:
                logger.info("Marauder reconnect attempt...")
                self.disconnect()
                if not self.connect():
                    return []
            else:
                return []

        anomalies = []
        now = time.time()

        # 1. Process deauth events → detect bursts (always, regardless of mode)
        anomalies.extend(self._process_deauth_events())

        # 2. Phase cycling — only run one scan type per poll to minimize time off deauth
        if (now - self._last_scan_time) >= self._scan_interval:
            self._last_scan_time = now
            anomalies.extend(self._run_ap_scan(managed_aps, known_ssids))

        elif (now - self._last_probe_time) >= self._probe_interval:
            self._last_probe_time = now
            anomalies.extend(self._run_probe_scan(known_ssids))

        elif (now - self._last_pwnagotchi_time) >= self._pwnagotchi_interval:
            self._last_pwnagotchi_time = now
            anomalies.extend(self._run_pwnagotchi_scan())

        return anomalies

    # ── Phase 2: AP Scan ──────────────────────────────────

    def _run_ap_scan(self, managed_aps, known_ssids):
        """Switch to scanap, dwell, cross-reference, switch back."""
        anomalies = []

        try:
            self._switch_mode("scanap")
            time.sleep(self._scan_dwell)

            scanned = list(self._ap_scan_buffer)
            new_count = 0

            for ap in scanned:
                bssid = ap["bssid"]
                ssid = ap["ssid"]

                # Check for rogue AP: known SSID but unknown BSSID
                if ssid in known_ssids and bssid not in managed_aps:
                    anomalies.append({
                        "type": "rogue_ap",
                        "source": "marauder",
                        "bssid": bssid,
                        "ssid": ssid,
                        "channel": ap.get("channel", 0),
                        "rssi": ap.get("rssi", 0),
                    })

                info = self._known_rf_aps.get(bssid, {})
                if info.get("count", 0) <= 1:
                    new_count += 1

            rogue_count = len(anomalies)
            try:
                self.blackboard.post_activity(
                    f"[RF] AP scan: {len(scanned)} observed, "
                    f"{new_count} new, {rogue_count} rogue, "
                    f"{len(self._known_rf_aps)} total tracked",
                    entry_type="OK" if rogue_count == 0 else "WARN"
                )
            except Exception:
                pass

            logger.info(f"[RF] AP scan: {len(scanned)} APs, {new_count} new, "
                        f"{rogue_count} rogue, {len(self._known_rf_aps)} total tracked")

        except Exception as e:
            logger.error(f"Marauder AP scan error: {e}")

        finally:
            self._switch_mode("sniffdeauth")

        return anomalies

    # ── Phase 3: Probe Request Scan ───────────────────────

    def _run_probe_scan(self, known_ssids):
        """Switch to sniffprobe, dwell, analyze probe patterns, switch back.

        Intelligence gathered:
        - Devices probing for known SSIDs (pre-attack recon)
        - Devices with unusual probe counts (scanning/enumeration)
        - Per-device SSID history for fingerprinting
        """
        anomalies = []

        try:
            self._probe_buffer.clear()
            self._switch_mode("sniffprobe")
            time.sleep(self._probe_dwell)

            sweep = list(self._probe_buffer)
            unique_devices = set()
            suspicious_probes = []

            for probe in sweep:
                src = probe["src"]
                ssid = probe["ssid"]
                unique_devices.add(src)

                # Suspicious: unknown device probing for our network SSIDs
                if ssid and ssid in known_ssids:
                    suspicious_probes.append(probe)

            # Generate anomalies for suspicious probing
            # Group by source MAC to avoid flooding
            suspicious_by_src = defaultdict(list)
            for p in suspicious_probes:
                suspicious_by_src[p["src"]].append(p["ssid"])

            for src, ssids in suspicious_by_src.items():
                anomalies.append({
                    "type": "suspicious_probe",
                    "source": "marauder",
                    "mac": src,
                    "probed_ssids": list(set(ssids)),
                    "count": len(ssids),
                })

            # Post activity summary
            try:
                suspicious_count = len(suspicious_by_src)
                self.blackboard.post_activity(
                    f"[RF] Probe scan: {len(sweep)} requests from "
                    f"{len(unique_devices)} devices, "
                    f"{suspicious_count} probing known SSIDs, "
                    f"{len(self._probe_devices)} total devices tracked",
                    entry_type="OK" if suspicious_count == 0 else "WARN"
                )
            except Exception:
                pass

            logger.info(
                f"[RF] Probe scan: {len(sweep)} requests, "
                f"{len(unique_devices)} devices, "
                f"{len(suspicious_by_src)} suspicious, "
                f"{len(self._probe_devices)} total tracked")

        except Exception as e:
            logger.error(f"Marauder probe scan error: {e}")

        finally:
            self._switch_mode("sniffdeauth")

        return anomalies

    # ── Phase 4: Pwnagotchi Detection ─────────────────────

    def _run_pwnagotchi_scan(self):
        """Switch to sniffpwnagotchi, dwell, detect war-drivers, switch back.

        Pwnagotchis broadcast identifiable beacon frames with custom
        vendor-specific information elements. Detection = someone nearby
        is actively capturing WPA handshakes with an AI-assisted tool.

        This is a CRITICAL alert — immediate DEFCON escalation.
        """
        anomalies = []

        try:
            self._pwnagotchi_buffer.clear()
            self._switch_mode("sniffpwnagotchi")
            time.sleep(self._pwnagotchi_dwell)

            detections = list(self._pwnagotchi_buffer)

            if detections:
                # Deduplicate by MAC for this sweep
                seen_macs = {}
                for d in detections:
                    mac = d["mac"]
                    if mac not in seen_macs:
                        seen_macs[mac] = d

                for mac, det in seen_macs.items():
                    info = self._pwnagotchi_detections.get(mac, {})
                    anomalies.append({
                        "type": "pwnagotchi_detected",
                        "source": "marauder",
                        "mac": mac,
                        "name": det.get("name", info.get("name", "unknown")),
                        "sightings": info.get("count", 1),
                    })

                # Voice alert for pwnagotchi detection
                if self.voice:
                    try:
                        names = ", ".join(d.get("name", "unknown") for d in seen_macs.values())
                        self.voice.speak(
                            f"Warning. Pwnagotchi detected in perimeter. "
                            f"Device {'names' if len(seen_macs) > 1 else 'name'}: {names}. "
                            f"Someone is hunting W.P.A. handshakes."
                        )
                    except Exception:
                        pass

                try:
                    pwna_desc = ", ".join(
                        f"{d.get('name', '?')} ({m})" for m, d in seen_macs.items())
                    self.blackboard.post_activity(
                        f"[RF] PWNAGOTCHI DETECTED: {len(seen_macs)} war-driver(s) "
                        f"in range — {pwna_desc}",
                        entry_type="CRITICAL"
                    )
                except Exception:
                    pass

                pwna_log = ", ".join(
                    f"{d.get('name', '?')} ({m})" for m, d in seen_macs.items())
                logger.warning(
                    f"[RF] PWNAGOTCHI DETECTED: {len(seen_macs)} device(s) — {pwna_log}")
            else:
                try:
                    self.blackboard.post_activity(
                        f"[RF] Pwnagotchi sweep: clear — "
                        f"no war-drivers detected",
                        entry_type="OK"
                    )
                except Exception:
                    pass

                logger.info("[RF] Pwnagotchi sweep: clear")

        except Exception as e:
            logger.error(f"Marauder pwnagotchi scan error: {e}")

        finally:
            self._switch_mode("sniffdeauth")

        return anomalies

    # ── Deauth Burst Detection ────────────────────────────

    def _process_deauth_events(self):
        """Check deauth rate tracker for burst attacks."""
        anomalies = []
        now = time.time()
        window = self._burst_window
        threshold = self._burst_threshold

        expired_srcs = []
        for src, timestamps in self._deauth_rate.items():
            recent = [t for t in timestamps if (now - t) <= window]
            self._deauth_rate[src] = recent

            if not recent:
                expired_srcs.append(src)
                continue

            if len(recent) >= threshold:
                targets = defaultdict(int)
                for ts, s, d in self._deauth_events:
                    if s == src and (now - ts) <= window:
                        targets[d] += 1
                top_target = max(targets, key=targets.get) if targets else "ff:ff:ff:ff:ff:ff"

                anomalies.append({
                    "type": "deauth_attack",
                    "source": "marauder",
                    "src": src,
                    "dst": top_target,
                    "count": len(recent),
                    "window": window,
                    "mac": src,
                })

                self._deauth_rate[src] = []

        for src in expired_srcs:
            del self._deauth_rate[src]

        return anomalies

    # ── Status Interface ───────────────────────────────────

    def get_status(self):
        """Return current Marauder status for defense dashboard."""
        return {
            "available": self._available or False,
            "mode": self._current_mode,
            "known_rf_aps": len(self._known_rf_aps),
            "deauth_events_total": self._deauth_total,
            "probe_devices": len(self._probe_devices),
            "probe_requests_total": self._probe_total,
            "pwnagotchi_detections": len(self._pwnagotchi_detections),
            "pwnagotchi_names": [
                d.get("name", "?") for d in self._pwnagotchi_detections.values()
            ],
            "last_ap_scan": self._last_scan_time,
            "last_probe_scan": self._last_probe_time,
            "last_pwnagotchi_scan": self._last_pwnagotchi_time,
        }

    def stop(self):
        """Shutdown Marauder monitor."""
        logger.info("Stopping MarauderMonitor...")
        self.disconnect()
        logger.info("MarauderMonitor stopped")
