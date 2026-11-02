#!/bin/sh
# Installs the helper as a systemd service when this system runs systemd. A
# failure never fails the package: the app offers to install the helper itself.
set -e

HELPER=/usr/lib/RouteWise/helper/routewise

case "$1" in
    configure)
        if [ -d /run/systemd/system ] && [ -f "$HELPER" ]; then
            chmod 0755 "$HELPER"
            "$HELPER" service install \
                || echo "routewise: could not install the helper service; the app will offer to install it" >&2
        fi
        ;;
esac

exit 0
