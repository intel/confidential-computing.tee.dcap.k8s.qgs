#!/bin/sh
test -S /var/run/tdx-qgs/qgs.socket && rm -f /var/run/tdx-qgs/qgs.socket
exec /usr/sbin/qgs --no-daemon "$@"
