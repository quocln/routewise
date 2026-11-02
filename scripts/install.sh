#!/bin/bash
# Routewise - macOS Installation Script
# Builds and installs routewise helper daemon and macOS app

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

HELPER_NAME="com.routewise.helper"
HELPER_INSTALL_DIR="/Library/PrivilegedHelperTools"
PLIST_PATH="/Library/LaunchDaemons/$HELPER_NAME.plist"
CONFIG_DIR="/Library/Application Support/RouteWise"
LOG_FILE="/var/log/routewise.log"
APP_INSTALL_DIR="/Applications"

echo -e "${GREEN}Routewise Installer${NC}"
echo "===================="

# Check root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: Please run with sudo${NC}"
    echo "  sudo $0"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# The user who invoked sudo. Needed for the commit stamp below and for handing
# the installed app back at the end. `sudo make install` runs this script
# through a second sudo inside make, which reports root as SUDO_USER; the
# checkout's owner is the user then.
ACTUAL_USER=${SUDO_USER:-$(whoami)}
if [ "$ACTUAL_USER" = "root" ]; then
    ACTUAL_USER=$(stat -f %Su "$PROJECT_DIR")
fi

# git refuses a repository owned by someone else, so asking it as root yields
# nothing. Read the commit as the invoking user and pass it into the builds.
COMMIT=$(sudo -u "$ACTUAL_USER" git -C "$PROJECT_DIR" rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Wait until launchd has fully forgotten the service. bootout is asynchronous:
# it returns while the job is still being torn down, and bootstrapping inside
# that window fails with EIO ("Input/output error"). A fixed sleep is a guess
# that gets it wrong exactly when the build is a cache hit and the rest of the
# install runs fast.
wait_for_unload() {
    local deadline=$((SECONDS + 30))
    while [ "$SECONDS" -lt "$deadline" ]; do
        if ! launchctl print system/$HELPER_NAME >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.2
    done
    return 1
}

# Build helper daemon and app as universal binaries (Intel + Apple Silicon).
# A helper missing this Mac's CPU type is rejected by launchd and the daemon
# never starts.
#
# Build as the invoking user, not root. A root build leaves root-owned files in
# build/, and every later build without sudo then fails to overwrite them.
# Earlier installers did build as root, so hand those trees back first. PATH is
# passed through because sudo would reset it and lose go.
cd "$PROJECT_DIR"
echo "Building universal helper daemon and macOS app..."
if [ "$ACTUAL_USER" != "root" ]; then
    for dir in "$PROJECT_DIR/build" \
        "$PROJECT_DIR/desktop/.next" "$PROJECT_DIR/desktop/out" \
        "$PROJECT_DIR/desktop/src-tauri/resources" "$PROJECT_DIR/desktop/src-tauri/target"; do
        [ -d "$dir" ] && chown -R "$ACTUAL_USER" "$dir"
    done
    sudo -u "$ACTUAL_USER" -H env PATH="$PATH" make app COMMIT="$COMMIT"
else
    make app COMMIT="$COMMIT"
fi

# Stop existing service. Only now: a build that fails must leave the running
# helper alone, and this keeps the time without one as short as possible.
if launchctl print system/$HELPER_NAME >/dev/null 2>&1; then
    echo "Stopping existing service..."
    launchctl bootout system/$HELPER_NAME 2>/dev/null || true
    if ! wait_for_unload; then
        echo -e "${YELLOW}Warning: $HELPER_NAME did not unload within 30s${NC}"
    fi
fi

# Create config directory
if [ ! -d "$CONFIG_DIR" ]; then
    echo "Creating config directory..."
    mkdir -p "$CONFIG_DIR"
fi

# Install helper binary
echo "Installing helper to $HELPER_INSTALL_DIR..."
cp "$PROJECT_DIR/build/$HELPER_NAME" "$HELPER_INSTALL_DIR/$HELPER_NAME"
chmod 755 "$HELPER_INSTALL_DIR/$HELPER_NAME"
chown root:wheel "$HELPER_INSTALL_DIR/$HELPER_NAME"

# Install config only when there is none. The installed file holds the user's
# own domain list, which the helper and the app both write to; copying the
# bundled starter config over it would silently discard their configuration.
#
# The helper keeps its config in routewise.db. On first start it imports
# config.yaml and renames it config.yaml.migrated, so once the database exists
# a starter YAML would never be read and is not copied.
if [ -f "$CONFIG_DIR/routewise.db" ]; then
    echo "Keeping existing config database at $CONFIG_DIR/routewise.db"
elif [ -f "$CONFIG_DIR/config.yaml" ]; then
    echo "Keeping existing config at $CONFIG_DIR/config.yaml (imported into routewise.db on first start)"
else
    echo "Installing default config..."
    cp "$PROJECT_DIR/config/starter-config.yaml" "$CONFIG_DIR/config.yaml"
    chmod 644 "$CONFIG_DIR/config.yaml"
    chown root:staff "$CONFIG_DIR/config.yaml"
fi

# Create log file
touch "$LOG_FILE"
chmod 644 "$LOG_FILE"

# Install launchd plist
echo "Installing launchd service..."
cat > "$PLIST_PATH" << PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>$HELPER_NAME</string>
    <key>ProgramArguments</key>
    <array>
        <string>$HELPER_INSTALL_DIR/$HELPER_NAME</string>
        <string>start</string>
        <string>--foreground</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>$LOG_FILE</string>
    <key>StandardErrorPath</key>
    <string>$LOG_FILE</string>
    <key>WorkingDirectory</key>
    <string>/tmp</string>
</dict>
</plist>
PLISTEOF
chmod 644 "$PLIST_PATH"
chown root:wheel "$PLIST_PATH"

# Start service. A bootstrap that lands while launchd is still reaping the old
# job fails with EIO; retry after waiting the job out rather than aborting the
# install, so the app bundle below still gets replaced.
echo "Starting service..."
HELPER_STARTED=0
for attempt in 1 2 3; do
    if launchctl bootstrap system "$PLIST_PATH" 2>&1; then
        HELPER_STARTED=1
        break
    fi
    echo "Bootstrap attempt $attempt failed; waiting for launchd to release the job..."
    wait_for_unload || true
done

if [ "$HELPER_STARTED" -eq 1 ]; then
    launchctl kickstart -k system/$HELPER_NAME
else
    echo -e "${RED}Error: could not bootstrap $HELPER_NAME${NC}"
    echo "  Continuing with the app install; the daemon is NOT running."
fi

# close app if it opened
if pgrep -f "RouteWise.app" > /dev/null; then
    echo "Closing RouteWise.app..."
    pkill -f "RouteWise.app" || true
    sleep 1
fi

# Install app
echo "Installing RouteWise.app to $APP_INSTALL_DIR..."
rm -rf "$APP_INSTALL_DIR/RouteWise.app"
cp -R "$PROJECT_DIR/build/RouteWise.app" "$APP_INSTALL_DIR/"

# Set permissions so user can run it (if installed by root, ownership is root)
echo "Setting ownership to $ACTUAL_USER..."
chown -R "$ACTUAL_USER:staff" "$APP_INSTALL_DIR/RouteWise.app"



# open app
echo "Opening RouteWise.app..."
open "$APP_INSTALL_DIR/RouteWise.app"

echo ""
if [ "$HELPER_STARTED" -eq 1 ]; then
    echo -e "${GREEN}Installation complete!${NC}"
else
    echo -e "${RED}Installation incomplete: the app is installed but the helper did not start.${NC}"
    echo "  Inspect: sudo launchctl print system/$HELPER_NAME"
    echo "  Retry:   sudo launchctl bootstrap system $PLIST_PATH"
fi
echo ""
echo "Commands:"
echo "  tail -f $LOG_FILE       - View logs"

if [ "$HELPER_STARTED" -ne 1 ]; then
    exit 1
fi
