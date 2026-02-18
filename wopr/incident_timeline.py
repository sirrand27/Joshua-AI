"""
W.O.P.R. Automated Incident Timeline Generator
Snapshots surrounding context when HIGH+ events fire,
producing structured timelines posted to Blackboard.
"""

import json
import logging
import time
from collections import deque
from datetime import datetime, timezone, timedelta

logger = logging.getLogger(__name__)


class IncidentTimeline:
    """Generates structured incident timelines from defense context.
    Triggered on HIGH+ severity events."""

    def __init__(self, blackboard, device_db, lookback_seconds=300,
                 dedup_window=600):
        self.blackboard = blackboard
        self.device_db = device_db
        self._lookback = lookback_seconds
        self._dedup_window = dedup_window
        self._anomaly_buffer = deque(maxlen=200)
        # Dedup: (mac, type) -> last timeline timestamp
        self._timeline_tracker = {}
        self._timeline_count = 0

    def record_anomaly(self, anomaly, severity, description):
        """Record every anomaly for timeline context (called every cycle)."""
        self._anomaly_buffer.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "type": anomaly.get("type", "unknown"),
            "mac": anomaly.get("mac", ""),
            "severity": severity,
            "description": description[:200],
            "source": anomaly.get("source", "unifi"),
        })

    def should_generate(self, anomaly, severity):
        """Check if this anomaly warrants a timeline."""
        if severity not in ("CRITICAL", "HIGH"):
            return False
        mac = anomaly.get("mac", "global")
        atype = anomaly.get("type", "unknown")
        key = (mac, atype)
        now = time.time()
        last = self._timeline_tracker.get(key, 0)
        if now - last < self._dedup_window:
            return False
        self._timeline_tracker[key] = now
        # Prune old entries
        expired = [k for k, v in self._timeline_tracker.items()
                   if now - v > self._dedup_window * 2]
        for k in expired:
            del self._timeline_tracker[k]
        return True

    def generate(self, triggering_anomaly, severity, description,
                 baseline=None, posture=None, diagnostics=None,
                 marauder=None, miner_monitor=None, correlation=None):
        """Generate and post a structured incident timeline."""
        self._timeline_count += 1
        now = datetime.now(timezone.utc)
        mac = triggering_anomaly.get("mac", "")

        # 1. Recent anomalies within lookback window
        cutoff = (now - timedelta(seconds=self._lookback)).isoformat()
        recent = [a for a in self._anomaly_buffer if a["timestamp"] >= cutoff]

        # 2. Device context
        device_context = None
        if mac and self.device_db:
            device = self.device_db.get_device(mac)
            if device:
                device_context = {
                    "mac": mac,
                    "hostname": device.get("hostname", "unknown"),
                    "oui": device.get("oui", ""),
                    "trust_level": device.get("trust_level", "unknown"),
                    "first_seen": device.get("first_seen", ""),
                    "alert_count": device.get("alert_count", 0),
                }

        # 3. Posture state
        device_posture = {}
        if posture and mac:
            try:
                all_postures = posture.get_active_threats()
                device_posture = next(
                    (t for t in all_postures if t.get("mac") == mac), {}
                )
            except Exception:
                pass

        # 4. RF status
        rf_status = {}
        if marauder:
            try:
                rf_status = marauder.get_status()
            except Exception:
                pass

        # 5. Diagnostics
        diag_summary = {}
        if diagnostics:
            try:
                diag_summary = {
                    "status": diagnostics.get_status(),
                    "degraded": diagnostics.get_degraded_subsystems(),
                }
            except Exception:
                pass

        # 6. Miner fleet (brief)
        miner_online = "N/A"
        if miner_monitor and getattr(miner_monitor, 'enabled', False):
            try:
                fleet = miner_monitor.get_fleet_summary()
                miner_online = f"{fleet.get('pool_online', '?')}/{fleet.get('total_workers', '?')}"
            except Exception:
                pass

        # 7. Correlation status
        corr_status = {}
        if correlation:
            try:
                corr_status = correlation.get_status()
            except Exception:
                pass

        # 8. Baseline summary
        baseline_summary = {}
        if baseline:
            try:
                baseline_summary = baseline.get_summary()
            except Exception:
                pass

        # Build timeline
        timeline = {
            "timeline_id": f"TL-{self._timeline_count:04d}",
            "generated_at": now.isoformat(),
            "trigger": {
                "type": triggering_anomaly.get("type", "unknown"),
                "severity": severity,
                "description": description,
                "mac": mac,
                "raw": {k: str(v)[:200] for k, v in triggering_anomaly.items()},
            },
            "context": {
                "recent_anomalies": recent[-20:],
                "anomaly_count_in_window": len(recent),
                "device": device_context,
                "device_posture": device_posture,
            },
            "system_state": {
                "baseline_ready": baseline_summary.get("baseline_ready", False),
                "total_clients": baseline_summary.get("total_known_clients", 0),
                "diagnostics": diag_summary,
                "rf_monitor": rf_status,
                "miners_online": miner_online,
                "correlation": corr_status,
            },
        }

        # Human-readable summary
        lines = [
            f"INCIDENT TIMELINE {timeline['timeline_id']}",
            f"Generated: {now.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            "",
            f"TRIGGER: [{severity}] {description}",
        ]
        if device_context:
            lines.append(
                f"DEVICE: {device_context['hostname']} ({mac}) "
                f"Trust: {device_context['trust_level']} "
                f"Alerts: {device_context['alert_count']}"
            )
        if device_posture:
            lines.append(
                f"POSTURE: {device_posture.get('posture', 'unknown')} "
                f"({device_posture.get('detections', 0)} detections)"
            )
        lines.append(
            f"CONTEXT: {len(recent)} anomalies in last "
            f"{self._lookback // 60} minutes"
        )
        if recent:
            lines.append("RECENT EVENTS:")
            for a in recent[-5:]:
                lines.append(f"  [{a['severity']}] {a['description'][:80]}")
        lines.append(
            f"SYSTEM: Baseline={'READY' if baseline_summary.get('baseline_ready') else 'LEARNING'} | "
            f"Clients: {baseline_summary.get('total_known_clients', 0)} | "
            f"Miners: {miner_online}"
        )

        timeline["human_summary"] = "\n".join(lines)

        # Post to Blackboard as finding
        try:
            self.blackboard.post_finding(
                title=f"Incident Timeline: {triggering_anomaly.get('type', 'unknown')} [{severity}]",
                severity=severity,
                description=timeline["human_summary"],
                host=mac,
                evidence=json.dumps(timeline, default=str),
            )
        except Exception as e:
            logger.error(f"Timeline post failed: {e}")

        logger.info(
            f"[TIMELINE] Generated {timeline['timeline_id']} for "
            f"[{severity}] {triggering_anomaly.get('type', 'unknown')} — "
            f"{len(recent)} context events"
        )

        return timeline
