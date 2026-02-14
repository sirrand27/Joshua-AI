#!/usr/bin/env python3
"""
W.O.P.R. Network Defense Sentry
Monitors the network via UniFi MCP and posts observations
to the Blackboard Live Activity feed.

Usage:
    python agent.py              # Normal operation (defense sentry)
    python agent.py --test       # Single inference test
    python agent.py --status     # Check service status
"""

import json
import logging
import signal
import sys
import time
import urllib.request
import urllib.error

from config import (
    AGENT_NAME, OLLAMA_URL, OLLAMA_MODEL,
    POLL_INTERVAL,
    LOG_FILE, LOG_LEVEL
)
from blackboard import BlackboardClient
from voice import VoiceClient
from learning import LearningEngine
from unifi_defense import UniFiDefenseLoop

# === Logging Setup ===
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("wopr")


class JoshuaAgent:
    """Network defense sentry — monitors UniFi, posts to Live Activity."""

    def __init__(self):
        self.blackboard = BlackboardClient()
        self.voice = VoiceClient()
        self.learning = LearningEngine(self.blackboard)
        self.defense = UniFiDefenseLoop(self.blackboard, self.voice, self.learning)
        self.running = False

    def run(self):
        """Main loop — start defense thread, then idle with heartbeat."""
        logger.info(f"=== {AGENT_NAME} starting (defense sentry mode) ===")
        logger.info(f"Blackboard: {self.blackboard.base_url}")

        # Check services
        if not self.blackboard.is_available():
            logger.error("Blackboard is not reachable. Waiting...")

        self.voice.check_available()
        logger.info(f"Voice: {'enabled' if self.voice.enabled else 'disabled'}")

        # Start UniFi Network Defense loop (background thread)
        try:
            self.defense.start()
            defense_status = "active"
        except Exception as e:
            logger.warning(f"UniFi Defense loop failed to start: {e}")
            defense_status = "inactive"

        # Announce presence
        self.blackboard.send_message(
            to_agent="operator",
            content=f"{AGENT_NAME} online. Defense sentry mode. "
                    f"Voice: {'active' if self.voice.enabled else 'inactive'}, "
                    f"Network Defense: {defense_status}.",
            message_type="status"
        )

        self.running = True

        # Main loop — just keep alive and monitor defense thread health
        while self.running:
            try:
                # Check if defense thread is still alive
                if not self.defense.is_running():
                    logger.error("Defense loop thread died — restarting")
                    try:
                        self.defense.start()
                    except Exception as e:
                        logger.error(f"Defense restart failed: {e}")

                time.sleep(POLL_INTERVAL)

            except KeyboardInterrupt:
                logger.info("Interrupted by user")
                self.running = False
            except Exception as e:
                logger.error(f"Agent loop error: {e}", exc_info=True)
                time.sleep(POLL_INTERVAL)

        # Shutdown
        self.defense.stop()
        logger.info(f"=== {AGENT_NAME} shutdown ===")
        self.blackboard.send_message(
            to_agent="operator",
            content=f"{AGENT_NAME} going offline.",
            message_type="status"
        )

    def test(self):
        """Single inference test."""
        print(f"Testing {AGENT_NAME} with Ollama ({OLLAMA_MODEL})...")
        payload = {
            "model": OLLAMA_MODEL,
            "messages": [
                {"role": "user", "content": "Professor Falken, status report."}
            ],
            "stream": False,
        }
        url = f"{OLLAMA_URL}/api/chat"
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            url, data=data, method="POST",
            headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                result = json.loads(resp.read())
                response = result.get("message", {}).get("content", "")
                print(f"\nJOSHUA: {response}")
                if self.voice.enabled:
                    self.voice.speak(response)
        except Exception as e:
            print(f"ERROR: {e}")

    def status(self):
        """Check all service connectivity."""
        print(f"=== {AGENT_NAME} Status ===")

        # Ollama
        try:
            url = f"{OLLAMA_URL}/api/tags"
            with urllib.request.urlopen(url, timeout=5) as resp:
                models = json.loads(resp.read())
                names = [m["name"] for m in models.get("models", [])]
                has_model = OLLAMA_MODEL in names or any(
                    OLLAMA_MODEL.split(":")[0] in n for n in names
                )
                print(f"Ollama: ONLINE ({len(names)} models, "
                      f"{OLLAMA_MODEL}: {'YES' if has_model else 'NOT FOUND'})")
        except Exception as e:
            print(f"Ollama: OFFLINE ({e})")

        # Blackboard
        bb_status = "ONLINE" if self.blackboard.is_available() else "OFFLINE"
        print(f"Blackboard: {bb_status} ({self.blackboard.base_url})")

        # Voice
        voice_status = "ONLINE" if self.voice.check_available() else "OFFLINE"
        print(f"Voice: {voice_status} ({self.voice.host}:{self.voice.port})")

        # UniFi MCP
        from config import UNIFI_MCP_URL
        try:
            url = f"{UNIFI_MCP_URL}/mcp"
            with urllib.request.urlopen(url, timeout=5):
                print(f"UniFi MCP: ONLINE ({UNIFI_MCP_URL})")
        except Exception:
            print(f"UniFi MCP: OFFLINE ({UNIFI_MCP_URL})")

        # Defense loop
        defense_alive = self.defense.is_running()
        print(f"Defense Loop: {'ACTIVE' if defense_alive else 'INACTIVE'}")


def _handle_signal(sig, frame):
    """Graceful shutdown on SIGINT/SIGTERM."""
    logger.info(f"Received signal {sig}, shutting down...")
    sys.exit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    agent = JoshuaAgent()

    if len(sys.argv) > 1:
        if sys.argv[1] == "--test":
            agent.test()
        elif sys.argv[1] == "--status":
            agent.status()
        else:
            print(f"Usage: python agent.py [--test|--status]")
    else:
        agent.run()
