#!/usr/bin/env bash
# Driftwatch baseline hygiene check for Linux. Read-only.
#
# Prints one JSON document (schema driftwatch.hygiene/v1) describing auditd coverage, SSH hardening,
# the firewall, mandatory access control, kernel hardening, automatic updates and time sync. The agent
# embeds this script for the signed hygiene.collect action; it can also be run by hand:
#
#     sudo bash check-baseline.sh | python3 -m json.tool
#
# Each check is pass, fail or unknown (unknown: the state could not be read, usually without root).
# No dependency beyond coreutils; tools that are missing simply make the matching check unknown.
set -uo pipefail

SCRIPT_VERSION="1.0.0"
CHECKS=()
IS_ROOT=false
[ "$(id -u)" -eq 0 ] && IS_ROOT=true

json_escape() {
  local s=${1//\\/\\\\}
  s=${s//\"/\\\"}
  s=${s//$'\n'/\\n}
  s=${s//$'\r'/}
  s=${s//$'\t'/\\t}
  printf '%s' "$s"
}

# add_check id title severity expected status actual [detail]
add_check() {
  CHECKS+=("$(printf '{"id":"%s","title":"%s","severity":"%s","expected":"%s","status":"%s","actual":"%s","detail":"%s"}' \
    "$(json_escape "$1")" "$(json_escape "$2")" "$3" "$(json_escape "$4")" "$5" "$(json_escape "$6")" \
    "$(json_escape "${7:-}")")")
}

have() { command -v "$1" >/dev/null 2>&1; }

pass_if() { if [ "$1" = true ]; then echo pass; else echo fail; fi; }

# --- auditd --------------------------------------------------------------------------------------------
if have systemctl; then
  state=$(systemctl is-active auditd 2>/dev/null || true)
  add_check linux.auditd.running "auditd service running" high active "$(pass_if "$([ "$state" = active ] && echo true || echo false)")" "${state:-unknown}"
else
  if pgrep -x auditd >/dev/null 2>&1; then
    add_check linux.auditd.running "auditd service running" high active pass "running"
  else
    add_check linux.auditd.running "auditd service running" high active fail "not running"
  fi
fi

if have auditctl && $IS_ROOT; then
  rules=$(auditctl -l 2>/dev/null || true)
  if grep -q -- "execve" <<<"$rules"; then
    add_check linux.auditd.execve_rule "auditd execve rule loaded" high "execve rule" pass "loaded"
  else
    add_check linux.auditd.execve_rule "auditd execve rule loaded" high "execve rule" fail "no execve rule"
  fi
  if grep -q -- "/etc/audit" <<<"$rules"; then
    add_check linux.auditd.config_watch "auditd watches its own configuration" medium "watch on /etc/audit" pass "present"
  else
    add_check linux.auditd.config_watch "auditd watches its own configuration" medium "watch on /etc/audit" fail "absent"
  fi
else
  add_check linux.auditd.execve_rule "auditd execve rule loaded" high "execve rule" unknown "needs root and auditctl"
  add_check linux.auditd.config_watch "auditd watches its own configuration" medium "watch on /etc/audit" unknown "needs root and auditctl"
fi

# --- SSH -----------------------------------------------------------------------------------------------
sshd_value() {
  local key=$1 value=""
  if have sshd && $IS_ROOT; then
    value=$(sshd -T 2>/dev/null | awk -v k="$key" 'tolower($1)==k {print tolower($2); exit}')
  fi
  if [ -z "$value" ] && [ -r /etc/ssh/sshd_config ]; then
    value=$(cat /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null |
      awk -v k="$key" 'tolower($1)==k {print tolower($2); exit}')
  fi
  printf '%s' "$value"
}
if [ -e /etc/ssh/sshd_config ]; then
  v=$(sshd_value permitrootlogin)
  add_check linux.ssh.root_login_disabled "SSH root login (PermitRootLogin)" medium no \
    "$(pass_if "$([ "$v" = no ] && echo true || echo false)")" "${v:-default (prohibit-password)}"
  v=$(sshd_value passwordauthentication)
  add_check linux.ssh.password_auth_disabled "SSH password authentication (PasswordAuthentication)" medium no \
    "$(pass_if "$([ "$v" = no ] && echo true || echo false)")" "${v:-default (yes)}"
else
  add_check linux.ssh.root_login_disabled "SSH root login (PermitRootLogin)" medium no pass "sshd not installed"
  add_check linux.ssh.password_auth_disabled "SSH password authentication (PasswordAuthentication)" medium no pass "sshd not installed"
fi

# --- Firewall ------------------------------------------------------------------------------------------
fw_state="none"
if have ufw && $IS_ROOT && ufw status 2>/dev/null | grep -q "Status: active"; then
  fw_state="ufw active"
elif have firewall-cmd && firewall-cmd --state >/dev/null 2>&1; then
  fw_state="firewalld running"
elif have nft && $IS_ROOT && [ -n "$(nft list ruleset 2>/dev/null | grep -E 'hook input' || true)" ]; then
  fw_state="nftables input hook"
fi
if [ "$fw_state" = none ] && ! $IS_ROOT; then
  add_check linux.firewall.active "Host firewall active" medium active unknown "needs root to read rules"
else
  add_check linux.firewall.active "Host firewall active" medium active \
    "$(pass_if "$([ "$fw_state" != none ] && echo true || echo false)")" "$fw_state"
fi

# --- Mandatory access control --------------------------------------------------------------------------
mac="none"
if have getenforce; then
  mac="selinux $(getenforce 2>/dev/null | tr '[:upper:]' '[:lower:]')"
elif [ -r /sys/module/apparmor/parameters/enabled ] && [ "$(cat /sys/module/apparmor/parameters/enabled)" = Y ]; then
  mac="apparmor enabled"
fi
case $mac in
  "selinux enforcing"|"apparmor enabled") st=pass ;;
  *) st=fail ;;
esac
add_check linux.mac.enforcing "SELinux enforcing or AppArmor enabled" medium enforcing "$st" "$mac"

# --- Kernel hardening ----------------------------------------------------------------------------------
aslr=$(cat /proc/sys/kernel/randomize_va_space 2>/dev/null || echo "")
add_check linux.kernel.aslr "Full ASLR (randomize_va_space=2)" medium 2 \
  "$( [ -z "$aslr" ] && echo unknown || pass_if "$([ "$aslr" = 2 ] && echo true || echo false)")" "${aslr:-unreadable}"
ptrace=$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo "")
add_check linux.kernel.ptrace_restricted "ptrace restricted (yama ptrace_scope >= 1)" medium ">= 1" \
  "$( [ -z "$ptrace" ] && echo unknown || pass_if "$([ "$ptrace" -ge 1 ] && echo true || echo false)")" "${ptrace:-yama not loaded}"

# --- Updates and time ----------------------------------------------------------------------------------
upd="none"
if have systemctl; then
  for unit in unattended-upgrades.service apt-daily-upgrade.timer dnf-automatic.timer dnf-automatic-install.timer; do
    if [ "$(systemctl is-enabled "$unit" 2>/dev/null)" = enabled ]; then upd="$unit"; break; fi
  done
fi
add_check linux.updates.automatic "Automatic security updates enabled" low enabled \
  "$(pass_if "$([ "$upd" != none ] && echo true || echo false)")" "$upd"
if have timedatectl; then
  sync=$(timedatectl show -p NTPSynchronized --value 2>/dev/null || echo "")
  add_check linux.time.synchronized "System clock NTP-synchronized" medium yes \
    "$( [ -z "$sync" ] && echo unknown || pass_if "$([ "$sync" = yes ] && echo true || echo false)")" "${sync:-unknown}"
else
  add_check linux.time.synchronized "System clock NTP-synchronized" medium yes unknown "timedatectl missing"
fi

os_version="$(. /etc/os-release 2>/dev/null && printf '%s' "${PRETTY_NAME:-linux}") $(uname -r)"
collected=$(date -u +"%Y-%m-%dT%H:%M:%S.%6NZ" 2>/dev/null || date -u +"%Y-%m-%dT%H:%M:%SZ")
joined=$(IFS=,; printf '%s' "${CHECKS[*]}")
printf '{"schema":"driftwatch.hygiene/v1","platform":"linux","hostname":"%s","os_version":"%s","script_version":"%s","collected_at":"%s","is_admin":%s,"checks":[%s]}\n' \
  "$(json_escape "$(hostname)")" "$(json_escape "$os_version")" "$SCRIPT_VERSION" "$collected" "$IS_ROOT" "$joined"
