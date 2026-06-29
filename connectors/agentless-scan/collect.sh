#!/bin/sh
# collect.sh — XORCISM agentless host collector (Linux / Unix).
#
# Emits a JSON host snapshot (OS, installed packages, listening ports, a few CIS-style baseline checks)
# for the `agentless-scan` connector. No agent, read-only, no data leaves the host until YOU move the file.
#
#   Local / air-gapped ("mode déconnecté"):   sh collect.sh > snapshot.json
#   Over an admin SSH session (agentless):     ssh user@host 'sh -s' < collect.sh > snapshot.json
#   Many hosts: collect per host, then wrap:   {"hosts":[ <snap1>, <snap2>, ... ]}
#
# Then import:  python connectors/runner.py --connector agentless-scan --file snapshot.json
set -eu

j() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }   # JSON-escape a string

HOSTNAME="$(hostname 2>/dev/null || echo unknown)"
IP="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
KERNEL="$(uname -r 2>/dev/null || true)"

OS_ID=""; OS_NAME=""; OS_VER=""
if [ -r /etc/os-release ]; then
  . /etc/os-release 2>/dev/null || true
  OS_ID="${ID:-}"; OS_NAME="${ID:-${NAME:-}}"; OS_VER="${VERSION_ID:-}"
fi
[ -n "$OS_NAME" ] || OS_NAME="$(uname -s 2>/dev/null || echo unknown)"

# ── installed packages → "name\tversion" lines ────────────────────────────────
pkgs() {
  if command -v dpkg-query >/dev/null 2>&1; then
    dpkg-query -W -f='${Package}\t${Version}\n' 2>/dev/null
  elif command -v rpm >/dev/null 2>&1; then
    rpm -qa --qf '%{NAME}\t%{VERSION}\n' 2>/dev/null
  elif command -v apk >/dev/null 2>&1; then
    apk info -v 2>/dev/null | sed -E 's/^(.*)-([0-9].*)$/\1\t\2/'
  elif command -v pacman >/dev/null 2>&1; then
    pacman -Q 2>/dev/null | tr ' ' '\t'
  fi
}

# ── listening TCP ports ───────────────────────────────────────────────────────
ports() {
  if command -v ss >/dev/null 2>&1; then
    ss -H -tlnp 2>/dev/null | awk '{print $4}' | sed -E 's/.*:([0-9]+)$/\1/' | grep -E '^[0-9]+$' || true
  elif command -v netstat >/dev/null 2>&1; then
    netstat -tln 2>/dev/null | awk '/LISTEN/{print $4}' | sed -E 's/.*:([0-9]+)$/\1/' | grep -E '^[0-9]+$' || true
  fi
}

# ── a few CIS-style baseline checks → "id|title|result|severity" ──────────────
chk() { printf '%s|%s|%s|%s\n' "$1" "$2" "$3" "$4"; }
checks() {
  if [ -r /etc/ssh/sshd_config ]; then
    if grep -Eiq '^[[:space:]]*PermitRootLogin[[:space:]]+(yes|prohibit-password)' /etc/ssh/sshd_config; then
      chk "sshd-permitrootlogin" "SSH root login disabled" "fail" "high"
    else chk "sshd-permitrootlogin" "SSH root login disabled" "pass" "high"; fi
    if grep -Eiq '^[[:space:]]*PasswordAuthentication[[:space:]]+yes' /etc/ssh/sshd_config; then
      chk "sshd-passwordauth" "SSH password authentication disabled" "fail" "medium"
    else chk "sshd-passwordauth" "SSH password authentication disabled" "pass" "medium"; fi
  fi
  if command -v ufw >/dev/null 2>&1; then
    if ufw status 2>/dev/null | grep -qi 'Status: active'; then chk "host-firewall" "Host firewall enabled" "pass" "medium"
    else chk "host-firewall" "Host firewall enabled" "fail" "medium"; fi
  elif command -v firewall-cmd >/dev/null 2>&1; then
    if firewall-cmd --state 2>/dev/null | grep -qi running; then chk "host-firewall" "Host firewall enabled" "pass" "medium"
    else chk "host-firewall" "Host firewall enabled" "fail" "medium"; fi
  fi
  if [ -r /etc/login.defs ]; then
    md="$(awk '/^PASS_MAX_DAYS/{print $2}' /etc/login.defs 2>/dev/null | head -1)"
    if [ -n "$md" ] && [ "$md" -le 365 ] 2>/dev/null; then chk "pass-max-days" "Password max age <= 365 days" "pass" "low"
    else chk "pass-max-days" "Password max age <= 365 days" "fail" "low"; fi
    # value-bearing password-policy checks (the observed number is in the title so the policy validator
    # can compare it against the org policy's own threshold). Flagged 'fail' when outside a strict baseline.
    if [ -n "$md" ]; then
      if [ "$md" -le 90 ] 2>/dev/null; then chk "pwd-max-age" "Password max age = ${md} days" "pass" "medium"
      else chk "pwd-max-age" "Password max age = ${md} days" "fail" "medium"; fi
    fi
    ml="$(awk '/^PASS_MIN_LEN/{print $2}' /etc/login.defs 2>/dev/null | head -1)"
    [ -n "$ml" ] || ml="$(grep -hoE 'minlen[ =]+[0-9]+' /etc/security/pwquality.conf /etc/pam.d/* 2>/dev/null | grep -oE '[0-9]+' | head -1)"
    if [ -n "$ml" ]; then
      if [ "$ml" -ge 14 ] 2>/dev/null; then chk "pwd-min-length" "Password minimum length = ${ml}" "pass" "medium"
      else chk "pwd-min-length" "Password minimum length = ${ml}" "fail" "medium"; fi
    fi
  fi
}

# ── assemble JSON ─────────────────────────────────────────────────────────────
printf '{'
printf '"hostname":"%s",' "$(j "$HOSTNAME")"
[ -n "$IP" ] && printf '"ip":"%s",' "$(j "$IP")"
printf '"os":{"family":"linux","name":"%s","version":"%s","kernel":"%s"},' "$(j "$OS_NAME")" "$(j "$OS_VER")" "$(j "$KERNEL")"

printf '"packages":['
first=1
pkgs | while IFS="$(printf '\t')" read -r name ver; do
  [ -n "$name" ] || continue
  [ $first -eq 1 ] || printf ','
  printf '{"name":"%s","version":"%s"}' "$(j "$name")" "$(j "$ver")"
  first=0
done
printf '],'

printf '"listening":['
first=1
ports | sort -un | while read -r p; do
  [ -n "$p" ] || continue
  [ $first -eq 1 ] || printf ','
  printf '{"port":%s,"proto":"tcp"}' "$p"
  first=0
done
printf '],'

printf '"checks":['
first=1
checks | while IFS='|' read -r id title result sev; do
  [ -n "$id" ] || continue
  [ $first -eq 1 ] || printf ','
  printf '{"id":"%s","title":"%s","result":"%s","severity":"%s"}' "$(j "$id")" "$(j "$title")" "$(j "$result")" "$(j "$sev")"
  first=0
done
printf ']'
printf '}\n'
