#!/bin/bash
# Smart VPN Client - macOS Uninstallation Script

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

# Same label, plist and helper path as install.sh.
HELPER_NAME="com.routewise.helper"
HELPER_INSTALL_DIR="/Library/PrivilegedHelperTools"
PLIST_PATH="/Library/LaunchDaemons/$HELPER_NAME.plist"

echo -e "${RED}Smart VPN Client Uninstaller${NC}"
echo "================================"

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: Please run with sudo${NC}"
    exit 1
fi

# Stop service
if launchctl print system/$HELPER_NAME >/dev/null 2>&1; then
    echo "Stopping service..."
    launchctl bootout system/$HELPER_NAME 2>/dev/null || true
fi

# The helper runs the built-in WireGuard and Outline tunnels itself. Each utun
# belongs to the helper process, so the kernel removes it when that process
# exits. Unloading the job asks the helper to stop, which tears every tunnel
# down; wait for it to be gone, and force it only if it hangs, so no utun
# outlives the uninstall.
PID_FILE=/var/run/routewise.pid
if [ -f "$PID_FILE" ]; then
    HELPER_PID=$(cat "$PID_FILE" 2>/dev/null || true)
    if [[ "$HELPER_PID" =~ ^[0-9]+$ ]] && ps -p "$HELPER_PID" -o comm= 2>/dev/null | grep -q routewise; then
        echo "Waiting for the helper to close its tunnels..."
        for _ in $(seq 1 20); do
            kill -0 "$HELPER_PID" 2>/dev/null || break
            sleep 0.5
        done
        if kill -0 "$HELPER_PID" 2>/dev/null; then
            echo "The helper did not stop in time; terminating it."
            kill -TERM "$HELPER_PID" 2>/dev/null || true
            sleep 3
            kill -0 "$HELPER_PID" 2>/dev/null && kill -KILL "$HELPER_PID" 2>/dev/null || true
        fi
    fi
fi

# Remove the wildcard resolver files RouteWise wrote. The daemon removes them
# when it stops; this catches any left behind by a daemon that was killed.
# Only files starting with RouteWise's marker line are touched.
for f in /etc/resolver/*; do
    [ -f "$f" ] && head -n 1 "$f" | grep -q '^# Managed by RouteWise' && rm -f "$f"
done

# Remove files
echo "Removing files..."
rm -f /usr/local/bin/routewise
rm -f "$HELPER_INSTALL_DIR/$HELPER_NAME"
rm -f "$PLIST_PATH"
rm -f /var/run/routewise.pid

echo ""
echo -e "${GREEN}Uninstallation complete!${NC}"
echo ""
echo "Note: Config and logs preserved at:"
echo "  - ~/.routewise/config.yaml"
echo "  - /var/log/routewise.log (launchd output) and /var/log/routewise-YYYY-MM-DD.log (daily helper logs)"
echo "  - /Library/Application Support/RouteWise/routewise.db (settings, domain lists, the built-in"
echo "    WireGuard/Outline credentials, app preferences, and the access and activity history, with its"
echo "    -wal and -shm files; routewise.db.bak and routewise.db.v<N>.bak, the permanent pre-upgrade"
echo "    copy, hold the settings, credentials and preferences but no history)"
echo "  - /Library/Application Support/RouteWise/history.db.migrated (the old access history, if an earlier"
echo "    version left one behind)"
echo ""
echo "To remove completely:"
echo "  rm -rf ~/.routewise"
echo "  rm -f /var/log/routewise*.log"
echo "  rm -f \"/Library/Application Support/RouteWise/history.db\"*   # history.db.migrated and any leftover history.db"
echo "  rm -f \"/Library/Application Support/RouteWise/routewise.db\"*   # also deletes the stored VPN credentials, the .bak and .v<N>.bak copies, and all history"
