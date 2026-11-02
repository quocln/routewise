#!/bin/sh
# Stops and removes the helper service when the package is removed, not when
# it is upgraded (the new version's postinst replaces the running helper). The
# helper's config, data and logs stay.
set -e

case "$1" in
    remove|purge)
        if [ -d /run/systemd/system ]; then
            for helper in /usr/lib/routewise/routewise /usr/lib/RouteWise/helper/routewise; do
                if [ -f "$helper" ]; then
                    "$helper" service uninstall \
                        || echo "routewise: could not remove the helper service" >&2
                    break
                fi
            done
        fi
        ;;
esac

exit 0
