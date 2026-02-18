"""
W.O.P.R. Threat Intelligence Feed Integration
Pulls from public abuse.ch feeds, cross-references with observed
network traffic for C2/malware detection.

Feeds (all free, no API key):
- Feodo Tracker: C2 server IPs (Emotet, Dridex, TrickBot, QakBot)
- URLhaus: malicious URLs
- ThreatFox: IoC hostfile (domains)
"""

import json
import logging
import sqlite3
import threading
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Feed definitions
_FEEDS = {
    "feodo_c2": {
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
        "type": "ip_list",
        "description": "Feodo Tracker C2 IPs (recommended blocklist)",
    },
    "urlhaus_online": {
        "url": "https://urlhaus.abuse.ch/downloads/text_online/",
        "type": "url_list",
        "description": "URLhaus currently online malicious URLs",
    },
    "threatfox_iocs": {
        "url": "https://threatfox.abuse.ch/downloads/hostfile/",
        "type": "hostfile",
        "description": "ThreatFox IoC hostfile (malicious domains)",
    },
}

_FETCH_TIMEOUT = 30


class ThreatIntelEngine:
    """Threat intelligence feed manager with fast in-memory lookup."""

    def __init__(self, db_path, pull_interval=86400, enabled_feeds=None):
        self._db_path = db_path
        self._pull_interval = pull_interval
        self._enabled_feeds = enabled_feeds or list(_FEEDS.keys())
        self._lock = threading.Lock()
        self._last_pull = 0
        self._pull_count = 0

        # In-memory sets for fast matching
        self._bad_ips = set()
        self._bad_domains = set()

        self._init_db()
        self._load_from_db()

    def _conn(self):
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self):
        """Create threat_intel tables if not exists."""
        with self._lock:
            conn = self._conn()
            try:
                conn.executescript("""
                    CREATE TABLE IF NOT EXISTS threat_intel (
                        indicator TEXT NOT NULL,
                        indicator_type TEXT NOT NULL
                            CHECK(indicator_type IN ('ip', 'domain', 'url')),
                        feed TEXT NOT NULL,
                        first_seen TEXT NOT NULL,
                        last_refreshed TEXT NOT NULL,
                        PRIMARY KEY (indicator, feed)
                    );
                    CREATE INDEX IF NOT EXISTS idx_threat_indicator
                        ON threat_intel(indicator);
                    CREATE TABLE IF NOT EXISTS threat_intel_meta (
                        feed TEXT PRIMARY KEY,
                        last_pull TEXT NOT NULL,
                        indicator_count INTEGER DEFAULT 0,
                        pull_status TEXT DEFAULT 'ok'
                    );
                """)
                conn.commit()
            finally:
                conn.close()

    def _load_from_db(self):
        """Load indicators from DB into in-memory sets."""
        conn = self._conn()
        try:
            rows = conn.execute(
                "SELECT indicator, indicator_type FROM threat_intel"
            ).fetchall()
            for r in rows:
                if r["indicator_type"] == "ip":
                    self._bad_ips.add(r["indicator"])
                elif r["indicator_type"] == "domain":
                    self._bad_domains.add(r["indicator"])
            if self._bad_ips or self._bad_domains:
                logger.info(
                    f"[THREAT_INTEL] Loaded from DB: {len(self._bad_ips)} IPs, "
                    f"{len(self._bad_domains)} domains"
                )
        finally:
            conn.close()

    def should_pull(self):
        """Check if it's time to refresh feeds."""
        return (time.time() - self._last_pull) >= self._pull_interval

    def pull_feeds(self):
        """Pull all enabled threat feeds. Returns total new indicators."""
        self._last_pull = time.time()
        self._pull_count += 1
        total_new = 0

        for feed_key in self._enabled_feeds:
            feed = _FEEDS.get(feed_key)
            if not feed:
                continue
            try:
                count = self._pull_feed(feed_key, feed)
                total_new += count
                logger.info(f"[THREAT_INTEL] Pulled {feed_key}: {count} indicators")
            except Exception as e:
                logger.error(f"[THREAT_INTEL] Feed pull failed for {feed_key}: {e}")
                self._update_meta(feed_key, 0, "error")

        logger.info(
            f"[THREAT_INTEL] Feed refresh #{self._pull_count}: {total_new} new, "
            f"totals: {len(self._bad_ips)} IPs, {len(self._bad_domains)} domains"
        )
        return total_new

    def _pull_feed(self, feed_key, feed_config):
        """Pull a single feed and update DB + in-memory sets."""
        url = feed_config["url"]
        feed_type = feed_config["type"]

        req = urllib.request.Request(url, method="GET")
        req.add_header("User-Agent", "WOPR-ThreatIntel/1.0")

        with urllib.request.urlopen(req, timeout=_FETCH_TIMEOUT) as resp:
            raw = resp.read().decode("utf-8", errors="replace")

        now = datetime.now(timezone.utc).isoformat()
        indicators = []

        if feed_type == "ip_list":
            for line in raw.strip().split("\n"):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(".")
                if len(parts) == 4 and all(p.isdigit() for p in parts):
                    indicators.append(("ip", line))

        elif feed_type == "url_list":
            for line in raw.strip().split("\n"):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    host = line.split("//", 1)[-1].split("/", 1)[0]
                    host = host.split(":")[0]
                    parts = host.split(".")
                    if len(parts) == 4 and all(p.isdigit() for p in parts):
                        indicators.append(("ip", host))
                    elif "." in host:
                        indicators.append(("domain", host.lower()))
                except Exception:
                    continue

        elif feed_type == "hostfile":
            for line in raw.strip().split("\n"):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1"):
                    domain = parts[1].lower().strip()
                    if domain and domain != "localhost" and "." in domain:
                        indicators.append(("domain", domain))

        # Store in DB and update in-memory sets
        new_count = 0
        with self._lock:
            conn = self._conn()
            try:
                for ind_type, ind_value in indicators:
                    conn.execute("""
                        INSERT INTO threat_intel
                            (indicator, indicator_type, feed, first_seen, last_refreshed)
                        VALUES (?, ?, ?, ?, ?)
                        ON CONFLICT(indicator, feed) DO UPDATE SET
                            last_refreshed = excluded.last_refreshed
                    """, (ind_value, ind_type, feed_key, now, now))
                    new_count += 1

                    if ind_type == "ip":
                        self._bad_ips.add(ind_value)
                    elif ind_type == "domain":
                        self._bad_domains.add(ind_value)

                self._update_meta_conn(conn, feed_key, len(indicators), "ok", now)
                conn.commit()
            finally:
                conn.close()

        return new_count

    def _update_meta(self, feed_key, count, status):
        """Update feed metadata."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            conn = self._conn()
            try:
                self._update_meta_conn(conn, feed_key, count, status, now)
                conn.commit()
            finally:
                conn.close()

    def _update_meta_conn(self, conn, feed_key, count, status, now):
        """Update meta within existing connection."""
        conn.execute("""
            INSERT INTO threat_intel_meta (feed, last_pull, indicator_count, pull_status)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(feed) DO UPDATE SET
                last_pull = excluded.last_pull,
                indicator_count = excluded.indicator_count,
                pull_status = excluded.pull_status
        """, (feed_key, now, count, status))

    def check_ip(self, ip):
        """Check if an IP is in the threat database."""
        return ip in self._bad_ips

    def check_domain(self, domain):
        """Check if a domain is in the threat database."""
        return domain.lower() in self._bad_domains

    def lookup(self, indicator):
        """Full lookup with feed info. Returns list of dicts or None."""
        conn = self._conn()
        try:
            rows = conn.execute(
                "SELECT * FROM threat_intel WHERE indicator = ?",
                (indicator,)
            ).fetchall()
            return [dict(r) for r in rows] if rows else None
        finally:
            conn.close()

    def check_client_connections(self, clients):
        """Cross-reference network clients against threat database.
        Returns list of anomaly dicts for matches."""
        anomalies = []

        for client in clients:
            if not isinstance(client, dict):
                continue
            ip = client.get("ip", "")
            mac = client.get("mac", "").lower()
            hostname = client.get("hostname", client.get("name", "unknown"))

            if ip and self.check_ip(ip):
                feeds = [r["feed"] for r in (self.lookup(ip) or [])]
                anomalies.append({
                    "type": "threat_intel_match",
                    "source": "threat_intel",
                    "mac": mac,
                    "hostname": hostname,
                    "matched_indicator": ip,
                    "indicator_type": "ip",
                    "direction": "source",
                    "feeds": feeds,
                })

        return anomalies

    def get_status(self):
        """Return current threat intel engine status."""
        conn = self._conn()
        try:
            meta_rows = conn.execute(
                "SELECT * FROM threat_intel_meta"
            ).fetchall()
            feeds = {r["feed"]: dict(r) for r in meta_rows}
        finally:
            conn.close()

        return {
            "enabled": True,
            "bad_ips": len(self._bad_ips),
            "bad_domains": len(self._bad_domains),
            "pull_count": self._pull_count,
            "last_pull": self._last_pull,
            "feeds": feeds,
        }
