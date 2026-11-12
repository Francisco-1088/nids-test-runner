#!/usr/bin/env bash
# Pi Script Manager entrypoint (see manifest.json): one batch, no cron gate or jitter.
set -euo pipefail
TMNIDS=/opt/pimgr-tools/tmnids/tmNIDS
if [[ ! -x $TMNIDS ]]; then
  echo "tmNIDS is not installed on this Pi: assign the traffic-gen (or lab-full) profile" >&2
  exit 2
fi
# tmNIDS calls curl, nc and dig itself and can't be bound to an interface, so it follows the
# default route. Only interfaces without their own routing table (eth0) are supported for now.
table_var="PIMGR_TABLE_${PARAM_IFACE^^}"
if [[ -n ${!table_var:-} ]]; then
  echo "nids-tests can't send its traffic out $PARAM_IFACE yet; choose eth0" >&2
  exit 2
fi
exec python3 "$(dirname "$0")/pimgr_nids.py" "$TMNIDS"
