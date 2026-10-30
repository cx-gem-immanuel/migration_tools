#!/usr/bin/env bash
# Daily CxOne audit trail export: yesterday's severity and state changes.
#
# Cron example (every day at 01:15; cron mails any output if MAILTO is set):
#   15 1 * * * /opt/cxone/audit_trail/daily_audit_trail.sh >> /var/log/cxone_audit/cron.log 2>&1
set -euo pipefail

# --- edit these -------------------------------------------------------------
APP_DIR="/opt/cxone/audit_trail"            # folder with audit_trail.py, cxsupport.py, logsupport.py
CONFIG="$APP_DIR/config.ini"                # real tenant settings; keep it private (chmod 600)
PYTHON="${PYTHON:-/usr/bin/python3}"        # full path: cron has a minimal PATH (use a venv python if you have one)
OUT_DIR="/var/log/cxone_audit"              # one JSON file per day lands here
LOG_DIR="$OUT_DIR/logs"                     # detailed run logs
CHANGE_TYPES="severity,state"
KEEP_LOG_DAYS=30                            # run logs older than this are deleted
UTC_DAY=0                                   # 0 = yesterday on this machine's clock, 1 = yesterday in UTC
# ----------------------------------------------------------------------------

# Yesterday as YYYY-MM-DD (GNU date first, then BSD/macOS date).
if [ "$UTC_DAY" = "1" ]; then
    YESTERDAY="$(date -u -d 'yesterday' +%F 2>/dev/null || date -u -v-1d +%F)"
    FROM="${YESTERDAY}T00:00:00Z"
    TO="${YESTERDAY}T23:59:59.999999Z"
else
    YESTERDAY="$(date -d 'yesterday' +%F 2>/dev/null || date -v-1d +%F)"
    FROM="$YESTERDAY"           # a bare date is the whole local day of this machine
    TO="$YESTERDAY"
fi

mkdir -p "$OUT_DIR" "$LOG_DIR"

# Allow only one run at a time. The lock is a folder holding our pid; it is removed when
# the script ends, and a lock left behind by a crashed run (dead pid) is cleared.
LOCK_DIR="$OUT_DIR/.audit_trail.lock"
if ! mkdir "$LOCK_DIR" 2>/dev/null; then
    OLD_PID="$(cat "$LOCK_DIR/pid" 2>/dev/null || true)"
    if [ -n "$OLD_PID" ] && kill -0 "$OLD_PID" 2>/dev/null; then
        echo "$(date '+%F %T') previous run (pid $OLD_PID) is still active; exiting" >&2
        exit 1
    fi
    echo "$(date '+%F %T') removing a stale lock (pid ${OLD_PID:-unknown})" >&2
    rm -rf "$LOCK_DIR"
    mkdir "$LOCK_DIR"
fi
echo $$ > "$LOCK_DIR/pid"
trap 'rm -rf "$LOCK_DIR"' EXIT

cd "$APP_DIR"
echo "$(date '+%F %T') exporting $FROM to $TO (change types: $CHANGE_TYPES)"

# The script exits non-zero on any error, so cron reports failures.
"$PYTHON" audit_trail.py -c "$CONFIG" \
    --from "$FROM" --to "$TO" \
    --change-type "$CHANGE_TYPES" \
    --out "$OUT_DIR/" --log-dir "$LOG_DIR"

find "$LOG_DIR" -name 'cx_audit_trail_*.log' -mtime +"$KEEP_LOG_DAYS" -delete
echo "$(date '+%F %T') done"
