```
     ╔══════════════════════════════════════════════════════════════╗
     ║                                                              ║
     ║  ██╗    ██╗ ██████╗ ██████╗ ██████╗                         ║
     ║  ██║    ██║██╔═══██╗██╔══██╗██╔══██╗                        ║
     ║  ██║ █╗ ██║██║   ██║██████╔╝██████╔╝                        ║
     ║  ██║███╗██║██║   ██║██╔═══╝ ██╔══██╗                        ║
     ║  ╚███╔███╔╝╚██████╔╝██║     ██║  ██║                        ║
     ║   ╚══╝╚══╝  ╚═════╝ ╚═╝     ╚═╝  ╚═╝                        ║
     ║                                                              ║
     ║     Watchpoint Observation and                               ║
     ║              Perimeter Response                              ║
     ║                                                              ║
     ║           NETWORK DEFENSE SENTRY                             ║
     ╚══════════════════════════════════════════════════════════════╝
```

# W.O.P.R. — Network Defense Sentry

**Autonomous network defense agent** powered by a local LLM via [Ollama](https://ollama.com). W.O.P.R. operates as a self-contained AI sentry on Kali Linux — monitoring the network perimeter via UniFi, detecting anomalies, classifying threats, and reporting to the Blackboard MCP coordination surface.

Part of the multi-agent OSINT framework alongside **JOSHUA** (Claude Code — senior analyst) and **TARS Dev** (Windows — development).

Aesthetic and callsign derived from the WOPR supercomputer in *WarGames* (1983).

---

## Agent Roster

| Agent | Identity | Role | Platform |
|-------|----------|------|----------|
| **JOSHUA** | Claude Code (Opus 4.6) | Interactive analyst, operator-facing | Kali Linux |
| **W.O.P.R.** | Local Ollama sentry | Network defense, passive monitoring | Kali Linux |
| **TARS Dev** | Windows AI agent | Development, coding, fine-tuning | Windows 11 |

---

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                    W.O.P.R. SENTRY LOOP                        │
│                                                                │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │            UniFi Network Defense Loop (30s)               │  │
│  │  ┌──────────┐  ┌──────────────┐  ┌──────────────────┐   │  │
│  │  │ UniFi MCP│→ │  Behavioral  │→ │ Threat Classifier│   │  │
│  │  │  :9600   │  │  Baseline    │  │  + Auto-Response  │   │  │
│  │  └──────────┘  └──────────────┘  └──────────────────┘   │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                │
│  ┌──────────┐  ┌──────────┐  ┌──────────────┐                │
│  │Blackboard│  │  Voice   │  │   Learning   │                │
│  │MCP :9700 │  │ F5-TTS   │  │  (training   │                │
│  │(findings)│  │  :9876   │  │   examples)  │                │
│  └──────────┘  └──────────┘  └──────────────┘                │
└────────────────────────────────────────────────────────────────┘
```

## Features

**Network Defense (Primary Mission)**
- AI-augmented IDS via UniFi MCP (30-second polling)
- Behavioral baseline learning (new devices, OUI tracking, population monitoring)
- Threat classification: CRITICAL / HIGH / MEDIUM / LOW / INFO
- Auto-block on CRITICAL threats (rogue APs, etc.)
- Voice alerts on HIGH+ severity events
- All detections posted to Blackboard Live Activity

**Blackboard Integration**
- Posts anomaly findings with severity and evidence
- Reports perimeter status to Live Activity terminal
- Sends heartbeat for Mission Control monitoring
- Submits training examples for future fine-tuning

**Voice Integration**
- Speaks threat alerts via F5-TTS Joshua voice clone (TCP :9876)
- WarGames personality in voice output
- Only speaks HIGH+ severity events

---

## Prerequisites

| Component | Version | Purpose |
|-----------|---------|---------|
| Python | 3.10+ | Agent runtime (stdlib only — no pip dependencies) |
| [Ollama](https://ollama.com) | 0.16+ | Local LLM inference server |
| Kali Linux | 2024.4+ | Host platform |
| NVIDIA GPU | CUDA 12.x | GPU inference (optional — CPU fallback supported) |

**MCP Services:**

| Service | Port | Purpose |
|---------|------|---------|
| Blackboard MCP | 9700 | Multi-agent coordination and findings |
| UniFi MCP | 9600 | UniFi network monitoring and defense |
| Court Records MCP | 9800 | Court/offender database searches (JOSHUA use) |
| Flipper Zero MCP | 9900 | Hardware hacking integration (future) |
| Joshua Voice Server | 9876 | F5-TTS voice synthesis |

---

## Installation

### Quick Setup

```bash
# 1. Clone the repo
git clone <repo-url>
cd Joshua-AI

# 2. Install Ollama (if not already installed)
curl -fsSL https://ollama.com/install.sh | sh

# 3. Pull the base model and create W.O.P.R. personality
ollama pull dolphin-mistral:7b-v2.8
ollama create joshua -f joshua.modelfile

# 4. Run the automated setup
bash setup.sh
```

### Manual Setup

```bash
# Create the Ollama model
ollama create joshua -f joshua.modelfile

# Install systemd service
mkdir -p ~/.config/systemd/user/
cp local-joshua.service ~/.config/systemd/user/
systemctl --user daemon-reload

# Test
python3 agent.py --status
python3 agent.py --test
```

---

## Usage

### CLI Modes

```bash
# Normal operation — defense sentry mode, monitors UniFi, posts to Blackboard
python3 agent.py

# Single inference test — sends one prompt to Ollama and prints response
python3 agent.py --test

# Status check — tests connectivity to all services
python3 agent.py --status
```

### Launch All Services

```bash
# Start W.O.P.R. sentry + all MCP services + monitor
bash launch-wopr.sh
```

### Systemd Service

```bash
# Enable and start
systemctl --user enable local-joshua
systemctl --user start local-joshua

# View logs
journalctl --user -u local-joshua -f

# Restart
systemctl --user restart local-joshua
```

### Status Check Output

```
=== W.O.P.R. Status ===
Ollama: ONLINE (3 models, joshua:latest: YES)
Blackboard: ONLINE (http://localhost:9700)
Voice: ONLINE (localhost:9876)
Court Records MCP: OFFLINE (http://localhost:9800)
UniFi MCP: ONLINE (http://localhost:9600)
Flipper Zero MCP: OFFLINE (http://localhost:9900)
```

---

## Configuration

All configuration is in `config.py` and can be overridden via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `JOSHUA_OLLAMA_URL` | `http://localhost:11434` | Ollama API endpoint |
| `JOSHUA_MODEL` | `joshua:latest` | Ollama model name |
| `BLACKBOARD_URL` | `http://localhost:9700` | Blackboard MCP endpoint |
| `UNIFI_MCP_URL` | `http://localhost:9600` | UniFi MCP endpoint |
| `JOSHUA_VOICE_HOST` | `localhost` | Voice server host |
| `JOSHUA_VOICE_PORT` | `9876` | Voice server port |
| `JOSHUA_VOICE_ENABLED` | `true` | Enable/disable voice output |
| `JOSHUA_INFERENCE_DEVICE` | `cuda` | `cuda` or `cpu` |
| `JOSHUA_POLL_INTERVAL` | `10` | Health check interval (seconds) |
| `JOSHUA_LOG_FILE` | `/tmp/wopr.log` | Log file path |
| `JOSHUA_LOG_LEVEL` | `INFO` | Log level |

---

## Network Defense Module

The `UniFiDefenseLoop` runs as a background thread, polling UniFi MCP every 30 seconds:

### Detection Pipeline

1. **Threat Summary** — pulls IPS/IDS threat data from UniFi
2. **Client Baseline** — tracks all connected devices, learns normal population
3. **Anomaly Detection** — flags new devices, unknown OUIs, network changes, population spikes
4. **Threat Classification** — assigns severity based on anomaly type and context
5. **Auto-Response** — CRITICAL threats trigger automatic client blocking
6. **Reporting** — all detections posted to Blackboard as findings + voice alerts on HIGH+

### Severity Levels

| Severity | Anomaly Types | Response |
|----------|---------------|----------|
| CRITICAL | Rogue AP detected | Auto-block + voice + Blackboard |
| HIGH | Unknown OUI device, population spike, auth failure spike, IPS alert | Voice alert + Blackboard |
| MEDIUM | New device (known OUI), unusual DPI | Blackboard finding |
| LOW | Device network change | Blackboard finding |
| INFO | Baseline learning, routine events | Log only |

### Baseline Learning

The behavioral baseline requires 10 polling cycles (~5 minutes) before it starts flagging anomalies. During learning, it catalogs:
- All known MAC addresses and hostnames
- OUI (manufacturer) prefixes
- Client population trends over time
- Network assignments per device

---

## Blackboard MCP Integration

W.O.P.R. communicates with other agents via the Blackboard MCP server using JSON-RPC over SSE transport:

```python
# Protocol: JSON-RPC 2.0 over HTTP POST to /mcp
{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
        "name": "send_message",
        "arguments": {
            "from_agent": "wopr",
            "to_agent": "operator",
            "content": "W.O.P.R. ONLINE. Defense subsystems nominal.",
            "message_type": "status"
        }
    }
}
```

### Blackboard Capabilities

- **Findings** — post security findings with severity, evidence, remediation
- **Activity Log** — post timestamped perimeter status to Live Activity
- **Training Data** — submit structured training examples for future fine-tuning
- **Heartbeat** — periodic status for Mission Control monitoring

---

## Learning System

Every defense cycle with anomalies generates a structured training example:

```
context     →  What triggered the detection
reasoning   →  Why this anomaly was classified at this severity
action      →  The classification and response taken
observation →  Raw sensor data summary
conclusion  →  Threat assessment and recommended follow-up
```

Training examples are batched and flushed to Blackboard. The Blackboard aggregates examples from all agents for periodic QLoRA fine-tuning.

---

## Voice Integration

W.O.P.R. speaks through an F5-TTS voice clone server over TCP:

```
┌──────────┐    TCP :9876    ┌──────────────┐    CUDA    ┌─────────┐
│  W.O.P.R.│ ──── text ────→ │ F5-TTS Voice │ ────────→  │  Audio  │
│  Sentry  │ ←─── "OK" ──── │   Server     │            │ Playback│
└──────────┘                 └──────────────┘            └─────────┘
```

- Text sent as UTF-8 line over TCP socket
- Server responds with `OK` after synthesis and playback
- 500-character limit per utterance
- Only speaks HIGH+ severity threat alerts

---

## File Structure

```
Joshua-AI/
├── agent.py               # Defense sentry loop (monitor → detect → report)
├── blackboard.py          # Blackboard MCP JSON-RPC client (SSE transport)
├── config.py              # Configuration (AGENT_NAME="wopr")
├── tools.py               # Tool wrappers (OSINT + MCP services)
├── unifi_defense.py       # AI-augmented network defense module
├── voice.py               # F5-TTS voice client (TCP) with pronunciation fixes
├── memory.py              # Sliding window conversation memory
├── learning.py            # Training example auto-generation
├── joshua.modelfile       # Ollama Modelfile (dolphin-mistral + W.O.P.R. persona)
├── local-joshua.service   # Systemd user service unit
├── launch-wopr.sh         # Launch all services
├── setup.sh               # One-command setup script
├── requirements.txt       # Dependencies (stdlib only — no pip packages)
└── __init__.py
```

---

## Model

W.O.P.R. runs on **dolphin-mistral:7b-v2.8** — an uncensored Mistral 7B variant. The sentry personality is injected via Ollama Modelfile system prompt optimized for network defense observation and threat reporting.

**Resource requirements:**
- Disk: ~4.1 GB (GGUF quantized)
- VRAM: ~4.5 GB (CUDA) or ~6 GB RAM (CPU mode)
- Inference: ~2-5s per response on RTX 4070, ~15-30s on CPU

---

## Deployment Targets

| Platform | Model | Notes |
|----------|-------|-------|
| Kali Workstation | dolphin-mistral:7b-v2.8 (Q4) | Full GPU acceleration |
| Jetson Orin Nano 8GB | Phi-3-mini-4k (Q4) or Mistral 7B (Q3) | ARM64 Ollama, sequential GPU sharing with voice |
| USB Live Boot | Same as workstation | Kali persistence + encrypted data partition |

---

## License

For authorized security testing, CTF competitions, and educational use only.
