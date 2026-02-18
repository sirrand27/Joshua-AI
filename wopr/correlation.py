"""
W.O.P.R. Cross-Layer Correlation Engine
Correlates RF events (ESP32 Marauder) with network events (UniFi)
to detect compound attacks invisible to either source alone.

Patterns detected:
- Evil Twin: deauth + rogue AP with matching SSID
- Deauth→Reconnect: deauth burst + client reconnects to different AP
- Probe→Associate: suspicious probe + same device joins network
- Coordinated Attack: multiple deauth targets + population spike
"""

import logging
import time
from collections import deque

logger = logging.getLogger(__name__)

# Anomaly types that originate from RF sources
_RF_TYPES = {
    "deauth_attack", "unknown_ap", "suspicious_probe",
    "pwnagotchi_detected", "rogue_ap",
}


class CorrelationEngine:
    """Sliding-window correlation of RF + network events."""

    def __init__(self, correlation_window=120, max_buffer_size=500):
        self._window = correlation_window
        self._rf_events = deque(maxlen=max_buffer_size)
        self._net_events = deque(maxlen=max_buffer_size)
        # Track emitted correlations: (type, mac) -> timestamp
        self._emitted = {}
        self._emit_cooldown = 300  # 5 min dedup

    def ingest(self, anomaly):
        """Ingest an anomaly and run correlation checks.
        Called from _handle_anomaly() after individual processing.
        Returns list of synthetic correlated anomalies (may be empty)."""
        now = time.time()
        source = anomaly.get("source", "")
        atype = anomaly.get("type", "")

        # Don't ingest our own correlation outputs
        if source == "correlation":
            return []

        entry = (now, anomaly)
        if source in ("marauder", "flipper_rf") or atype in _RF_TYPES:
            self._rf_events.append(entry)
        else:
            self._net_events.append(entry)

        self._prune(now)

        correlations = []
        correlations.extend(self._check_evil_twin(now))
        correlations.extend(self._check_deauth_reconnect(now))
        correlations.extend(self._check_probe_associate(now))
        correlations.extend(self._check_coordinated_attack(now))

        return correlations

    def _prune(self, now):
        """Remove events outside the correlation window."""
        cutoff = now - self._window
        while self._rf_events and self._rf_events[0][0] < cutoff:
            self._rf_events.popleft()
        while self._net_events and self._net_events[0][0] < cutoff:
            self._net_events.popleft()
        expired = [k for k, v in self._emitted.items()
                   if now - v > self._emit_cooldown]
        for k in expired:
            del self._emitted[k]

    def _should_emit(self, corr_type, mac, now):
        """Dedup check — only emit once per (type, mac) per cooldown."""
        key = (corr_type, mac)
        if key in self._emitted:
            return False
        self._emitted[key] = now
        return True

    def _check_evil_twin(self, now):
        """EVIL TWIN: deauth on BSSID + unknown/rogue AP with same SSID."""
        results = []
        deauths = [(ts, a) for ts, a in self._rf_events
                   if a.get("type") == "deauth_attack"]
        rogue_aps = [(ts, a) for ts, a in self._rf_events
                     if a.get("type") in ("rogue_ap", "unknown_ap")]

        for d_ts, deauth in deauths:
            for r_ts, rogue in rogue_aps:
                if abs(d_ts - r_ts) > self._window:
                    continue
                rogue_ssid = rogue.get("ssid", "")
                rogue_bssid = rogue.get("bssid", rogue.get("mac", ""))
                if rogue_ssid and rogue_bssid:
                    if self._should_emit("evil_twin", rogue_bssid, now):
                        results.append({
                            "type": "evil_twin_detected",
                            "source": "correlation",
                            "mac": rogue_bssid,
                            "ssid": rogue_ssid,
                            "deauth_src": deauth.get("src", ""),
                            "deauth_target": deauth.get("dst", ""),
                            "deauth_count": deauth.get("count", 0),
                            "rogue_channel": rogue.get("channel", 0),
                            "rogue_rssi": rogue.get("rssi", 0),
                            "time_delta_s": round(abs(d_ts - r_ts), 1),
                            "correlation_confidence": "HIGH",
                        })
        return results

    def _check_deauth_reconnect(self, now):
        """DEAUTH→RECONNECT: deauth burst + client reconnects to different AP."""
        results = []
        deauths = [(ts, a) for ts, a in self._rf_events
                   if a.get("type") == "deauth_attack"]
        reconnects = [(ts, a) for ts, a in self._net_events
                      if a.get("type") in ("rapid_reconnect", "network_change")]

        for d_ts, deauth in deauths:
            target_mac = deauth.get("dst", "").lower()
            if target_mac == "ff:ff:ff:ff:ff:ff":
                continue  # Broadcast — skip for targeted correlation
            for r_ts, recon in reconnects:
                if abs(d_ts - r_ts) > self._window:
                    continue
                recon_mac = recon.get("mac", "").lower()
                if target_mac == recon_mac:
                    if self._should_emit("deauth_reconnect", recon_mac, now):
                        results.append({
                            "type": "deauth_reconnect_detected",
                            "source": "correlation",
                            "mac": recon_mac,
                            "hostname": recon.get("hostname", "unknown"),
                            "deauth_src": deauth.get("src", ""),
                            "deauth_count": deauth.get("count", 0),
                            "reconnect_type": recon.get("type", ""),
                            "new_network": recon.get("new_network",
                                                     recon.get("network", "")),
                            "time_delta_s": round(abs(d_ts - r_ts), 1),
                            "correlation_confidence": "MEDIUM",
                        })
        return results

    def _check_probe_associate(self, now):
        """PROBE→ASSOCIATE: suspicious probe + same device joins network."""
        results = []
        probes = [(ts, a) for ts, a in self._rf_events
                  if a.get("type") == "suspicious_probe"]
        new_devs = [(ts, a) for ts, a in self._net_events
                    if a.get("type") == "new_device"]

        for p_ts, probe in probes:
            probe_mac = probe.get("mac", "").lower()
            if not probe_mac:
                continue
            for n_ts, new_dev in new_devs:
                if abs(p_ts - n_ts) > self._window:
                    continue
                dev_mac = new_dev.get("mac", "").lower()
                if probe_mac == dev_mac:
                    if self._should_emit("probe_associate", dev_mac, now):
                        results.append({
                            "type": "probe_associate_detected",
                            "source": "correlation",
                            "mac": dev_mac,
                            "hostname": new_dev.get("hostname", "unknown"),
                            "probed_ssids": probe.get("probed_ssids", []),
                            "joined_network": new_dev.get("network", ""),
                            "time_delta_s": round(abs(p_ts - n_ts), 1),
                            "correlation_confidence": "MEDIUM",
                        })
        return results

    def _check_coordinated_attack(self, now):
        """COORDINATED: multiple deauth targets + population spike."""
        results = []
        deauths = [(ts, a) for ts, a in self._rf_events
                   if a.get("type") == "deauth_attack"]
        pop_spikes = [(ts, a) for ts, a in self._net_events
                      if a.get("type") == "population_spike"]

        if len(deauths) < 2:
            return results

        unique_targets = set(a.get("dst", "") for _, a in deauths)
        unique_srcs = set(a.get("src", "") for _, a in deauths)

        if len(unique_targets) >= 3 or len(unique_srcs) >= 2:
            for s_ts, spike in pop_spikes:
                for d_ts, _ in deauths:
                    if abs(d_ts - s_ts) <= self._window:
                        if self._should_emit("coordinated", "multi", now):
                            results.append({
                                "type": "coordinated_attack_detected",
                                "source": "correlation",
                                "mac": list(unique_srcs)[0] if unique_srcs else "",
                                "deauth_sources": list(unique_srcs),
                                "deauth_targets": list(unique_targets),
                                "deauth_count": len(deauths),
                                "population_current": spike.get("current_count", 0),
                                "population_average": spike.get("average_count", 0),
                                "correlation_confidence": "HIGH",
                            })
                        break
        return results

    def get_status(self):
        """Return current correlation engine status."""
        return {
            "enabled": True,
            "rf_buffer_size": len(self._rf_events),
            "net_buffer_size": len(self._net_events),
            "active_correlations": len(self._emitted),
            "window_seconds": self._window,
        }
