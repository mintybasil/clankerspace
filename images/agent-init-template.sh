#!/bin/sh
# agent-init — custom agent init script template
#
# This file is a template for customizing agent startup behavior.
# The VM Manager can inject a customized version at launch time via
# fctools ResourceSystem, replacing the default /etc/init.d/agent-init.
#
# The script runs on VM boot, after network is configured.
# It has access to:
#   - Proxy env vars ($http_proxy, $https_proxy) if configured
#   - curl with proxy CA trust
#   - Pi (if installed) at /usr/bin/pi
#   - Any injected files from the VM launch request
#   - Network: eth0 with the VM's IP
#
# ─────────────────────────────────────────────────────────────────────

echo "[agent-init] Starting agent environment..."

# Print network info
IP=$(ip addr show eth0 2>/dev/null | grep "inet " | awk '{print $2}')
echo "[agent-init] IP: ${IP:-not configured}"
echo "[agent-init] Proxy: ${http_proxy:-none}"

# Check if injected task file exists
if [ -f /home/agent/task.md ]; then
    echo "[agent-init] Task file found:"
    head -5 /home/agent/task.md
    echo "..."
fi

# Start Pi with the injected task (if available)
if command -v pi >/dev/null 2>&1; then
    echo "[agent-init] Starting Pi agent harness..."
    # Run Pi in non-interactive mode with the task
    if [ -f /home/agent/task.md ]; then
        pi --print "$(cat /home/agent/task.md)" 2>&1
    else
        echo "[agent-init] No task file, starting interactive Pi..."
        pi
    fi
else
    echo "[agent-init] Pi not installed. Shell ready."
    exec /bin/sh
fi