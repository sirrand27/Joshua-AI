#!/usr/bin/env bash
# ╔══════════════════════════════════════════════╗
# ║  W.O.P.R. LAUNCH SEQUENCE                   ║
# ║  Network defense sentry — voice + UniFi     ║
# ╚══════════════════════════════════════════════╝

DIR="$(dirname "$(readlink -f "$0")")"
PENTEST_DIR="$(dirname "$DIR")"
LOG_DIR="/tmp"

launch_service() {
    local name="$1"
    local check="$2"
    local cmd="$3"
    local log="$4"

    if pgrep -f "$check" >/dev/null 2>&1; then
        echo "[WOPR] $name — already running"
    else
        eval "$cmd" &>"$log" &
        sleep 1
        if pgrep -f "$check" >/dev/null 2>&1; then
            echo "[WOPR] $name — ONLINE"
        else
            echo "[WOPR] $name — FAILED (see $log)"
        fi
    fi
}

echo "╔══════════════════════════════════════╗"
echo "║     W.O.P.R. LAUNCH SEQUENCE        ║"
echo "╚══════════════════════════════════════╝"
echo ""

# 1. Blackboard MCP (port 9700)
launch_service \
    "Blackboard MCP (:9700)" \
    "python3.*blackboard.*server.py" \
    "cd '$PENTEST_DIR/blackboard' && python3 server.py" \
    "$LOG_DIR/blackboard_server.log"

# 2. Joshua Voice Server (port 9876)
if systemctl --user is-active joshua-voice >/dev/null 2>&1; then
    echo "[WOPR] Joshua Voice (:9876) — already running"
else
    systemctl --user start joshua-voice 2>/dev/null || echo "[WOPR] Joshua Voice (:9876) — no service (manual start needed)"
    echo "[WOPR] Joshua Voice (:9876) — ONLINE"
fi

# 3. UniFi MCP (port 9600)
launch_service \
    "UniFi MCP (:9600)" \
    "python3.*unifi_mcp.*server.py" \
    "cd '$PENTEST_DIR/unifi_mcp' && bash run.sh" \
    "$LOG_DIR/unifi_mcp.log"

# 4. W.O.P.R. Sentry Agent
launch_service \
    "W.O.P.R. Sentry" \
    "python3.*local_joshua.*agent.py" \
    "cd '$DIR' && python3 agent.py" \
    "$LOG_DIR/wopr.log"

echo ""
echo "╔══════════════════════════════════════╗"
echo "║   W.O.P.R. ONLINE — SENTRY ACTIVE   ║"
echo "╚══════════════════════════════════════╝"

# Keep terminal open if launched from desktop
if [ -n "$LAUNCHED_FROM_DESKTOP" ]; then
    echo ""
    echo "Press Enter to close this window..."
    read -r
fi
