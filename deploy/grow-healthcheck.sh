#!/bin/bash
# GROW healthcheck — restart a service that is "active" in systemd but no longer
# answering HTTP (a hung single-threaded node process looks healthy to systemd).
#
# Run every 30s by grow-healthcheck.timer. A service is restarted only after 2
# CONSECUTIVE failed checks (~1 min), so one slow response never causes a restart.
#
# Install (as root):
#   install -m 755 deploy/grow-healthcheck.sh /usr/local/bin/grow-healthcheck.sh
#   cp deploy/grow-healthcheck.service deploy/grow-healthcheck.timer /etc/systemd/system/
#   systemctl daemon-reload && systemctl enable --now grow-healthcheck.timer

STATE_DIR=/run/grow-healthcheck
mkdir -p "$STATE_DIR"

check() {
  local unit="$1" url="$2"
  local f="$STATE_DIR/$unit.fails"

  # Don't judge a service that is intentionally stopped/starting.
  systemctl is-active --quiet "$unit" || { rm -f "$f"; return; }

  if curl -fsS -m 8 -o /dev/null "$url" 2>/dev/null; then
    rm -f "$f"
    return
  fi

  local n=$(( $(cat "$f" 2>/dev/null || echo 0) + 1 ))
  echo "$n" > "$f"
  logger -t grow-healthcheck "$unit: no response from $url ($n/2)"
  if [ "$n" -ge 2 ]; then
    logger -t grow-healthcheck "$unit: restarting (unresponsive for 2 checks)"
    systemctl restart "$unit"
    rm -f "$f"
  fi
}

check grow-dashboard http://127.0.0.1:4318/login
check grow-collector http://127.0.0.1:4319/health
