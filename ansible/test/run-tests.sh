#!/usr/bin/env bash
#
# Runs the vspam_agent role against a real systemd container, installing the
# real package from the real signed repository. Needs Docker and ansible.
#
#   ./run-tests.sh              full run
#   KEEP=1 ./run-tests.sh       leave the container up afterwards
#
# Four scenarios:
#   A  fresh install       -> package, config, service, health endpoint
#   B  second run          -> zero changes (the role is idempotent)
#   C  Postfix wiring      -> restriction appended, and Postfix fails OPEN
#   D  config change       -> handler restarts the agent, health still answers
#
# C is the one worth reading. Postfix defaults to deferring every message with
# 451 when a policy service is unreachable, on a 100s timeout. The role turns
# that off before it adds the restriction that would depend on it.

set -euo pipefail

IMAGE="${IMAGE:-vspam-ansible-test:deb12}"
CONTAINER="${CONTAINER:-vspam-ansible-test}"

HERE="$(cd "$(dirname "$0")" && pwd)"
ROLES="$(cd "$HERE/.." && pwd)"
WORK="$(mktemp -d)"

pass=0
fail=0

cleanup() {
  if [ "${KEEP:-0}" != "1" ]; then
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    rm -rf "$WORK"
  else
    echo "KEEP=1: leaving $CONTAINER up, playbooks in $WORK"
  fi
}
trap cleanup EXIT

ok()   { pass=$((pass + 1)); printf '  \033[32mok\033[0m   %s\n' "$1"; }
bad()  { fail=$((fail + 1)); printf '  \033[31mFAIL\033[0m %s\n' "$1"; }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (want '$3', got '$2')"; fi; }
contains() {
  if printf '%s' "$2" | grep -qF -- "$3"; then ok "$1"; else bad "$1 (missing '$3')"; fi
}

need() {
  command -v "$1" >/dev/null 2>&1 || { echo "need $1 on PATH"; exit 2; }
}
need docker
need ansible-playbook

# --- the container ----------------------------------------------------------

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "building $IMAGE"
  docker build -q -t "$IMAGE" - >/dev/null <<'DOCKERFILE'
FROM debian:12-slim
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
      systemd systemd-sysv ca-certificates curl gnupg python3 procps \
    && rm -rf /var/lib/apt/lists/*
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
DOCKERFILE
fi

echo "booting $CONTAINER"
docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
docker run -d --name "$CONTAINER" \
  --privileged --cgroupns=host \
  --tmpfs /run --tmpfs /run/lock \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
  "$IMAGE" >/dev/null

state=""
for _ in $(seq 1 30); do
  state="$(docker exec "$CONTAINER" systemctl is-system-running 2>&1 || true)"
  case "$state" in running | degraded) break ;; esac
  sleep 1
done
case "$state" in
  running | degraded) ;;
  *) echo "systemd did not come up: $state"; exit 2 ;;
esac

# --- the play ---------------------------------------------------------------

cat >"$WORK/inventory.ini" <<INI
[mailservers]
$CONTAINER ansible_connection=community.docker.docker ansible_python_interpreter=/usr/bin/python3
INI

write_play() {
  cat >"$WORK/play.yml" <<YAML
---
- name: vspam_agent role test
  hosts: mailservers
  gather_facts: true
  roles:
    - role: vspam_agent
      vars:
$1
YAML
}

run_play() {
  ANSIBLE_ROLES_PATH="$ROLES/roles" \
  ANSIBLE_HOST_KEY_CHECKING=False \
  ANSIBLE_STDOUT_CALLBACK=default \
    ansible-playbook -i "$WORK/inventory.ini" "$WORK/play.yml" 2>&1
}

# The recap line is the only reliable place to read the change count from.
changed_count() {
  printf '%s' "$1" | sed -n 's/.*changed=\([0-9]*\).*/\1/p' | tail -1
}
failed_count() {
  printf '%s' "$1" | sed -n 's/.*failed=\([0-9]*\).*/\1/p' | tail -1
}

in_c() { docker exec "$CONTAINER" sh -c "$1" 2>&1 || true; }

# --- A: fresh install -------------------------------------------------------

echo
echo "A. fresh install"
write_play "        vspam_agent_log_level: info"
out="$(run_play)" || true
check "play succeeded" "$(failed_count "$out")" "0"
if [ "$(failed_count "$out")" != "0" ]; then printf '%s\n' "$out" | tail -40; fi

check "package installed" "$(in_c 'dpkg-query -W -f=\${Status} vspam-agent')" "install ok installed"
check "service is active" "$(in_c 'systemctl is-active vspam-agent')" "active"
check "service is enabled" "$(in_c 'systemctl is-enabled vspam-agent')" "enabled"

cfg="$(in_c 'cat /etc/vspam/agent.yml')"
contains "config is role-managed" "$cfg" "Ansible managed"
contains "http check enabled"     "$cfg" "http_enabled: true"
contains "dnsbl zone set"         "$cfg" "dnsbl_zone: dnsbl.vspam.org"

check "config mode is 0640" "$(in_c 'stat -c %a /etc/vspam/agent.yml')" "640"
check "config group is vspam" "$(in_c 'stat -c %G /etc/vspam/agent.yml')" "vspam"

health="$(in_c 'curl -sS --max-time 5 http://127.0.0.1:10046/health')"
contains "health endpoint answers" "$health" "ok"

# The keyring is armored on purpose - apt reads it without a dearmor step.
contains "apt key installed armored" "$(in_c 'head -1 /etc/apt/keyrings/vspam-archive-keyring.asc')" "BEGIN PGP PUBLIC KEY"
contains "apt source uses signed-by" "$(in_c 'cat /etc/apt/sources.list.d/vspam.list')" "signed-by=/etc/apt/keyrings/vspam-archive-keyring.asc"

# --- B: idempotence ---------------------------------------------------------

echo
echo "B. second run changes nothing"
out="$(run_play)" || true
check "play succeeded" "$(failed_count "$out")" "0"
check "zero changes"   "$(changed_count "$out")" "0"
if [ "$(changed_count "$out")" != "0" ]; then
  printf '%s\n' "$out" | grep -E '^changed:' || true
fi

# --- C: Postfix wiring ------------------------------------------------------

echo
echo "C. Postfix wiring fails open"
docker exec "$CONTAINER" sh -c \
  'DEBIAN_FRONTEND=noninteractive apt-get install -y -qq postfix >/dev/null 2>&1' || true

check "postfix defers by default" \
  "$(in_c 'postconf -d smtpd_policy_service_default_action')" \
  "smtpd_policy_service_default_action = 451 4.3.5 Server configuration problem"

# A restriction list that is already load-bearing, to prove we append to it.
docker exec "$CONTAINER" postconf -e \
  'smtpd_recipient_restrictions = permit_mynetworks, reject_unauth_destination' >/dev/null

write_play "        vspam_agent_configure_postfix: true"
out="$(run_play)" || true
check "play succeeded" "$(failed_count "$out")" "0"
if [ "$(failed_count "$out")" != "0" ]; then printf '%s\n' "$out" | tail -40; fi

restrictions="$(in_c 'postconf -h smtpd_recipient_restrictions')"
contains "existing restrictions preserved" "$restrictions" "permit_mynetworks"
contains "relay control preserved"         "$restrictions" "reject_unauth_destination"
contains "policy service appended"         "$restrictions" "check_policy_service inet:127.0.0.1:10045"

check "fails open when agent is down" \
  "$(in_c 'postconf -h smtpd_policy_service_default_action')" "DUNNO"
check "short policy timeout" \
  "$(in_c 'postconf -h smtpd_policy_service_timeout')" "10s"

echo
echo "C2. Postfix wiring is idempotent"
out="$(run_play)" || true
check "zero changes" "$(changed_count "$out")" "0"

# One append per run would be the classic bug here.
occurrences="$(in_c 'postconf -h smtpd_recipient_restrictions' | grep -o 'check_policy_service' | wc -l | tr -d ' ')"
check "policy service listed once" "$occurrences" "1"

# The role edits main.cf on a live MTA. Postfix's own parser is the only
# authority on whether what we wrote is loadable.
check "postfix accepts the config" "$(in_c 'postfix check >/dev/null 2>&1 && echo valid || echo broken')" "valid"

# Postfix was installed but never started above, which is the state a first
# install leaves behind. `postfix reload` exits non-zero there, and the play
# must survive it rather than failing on a host that is not serving yet.
check "postfix was not running" "$(in_c 'postfix status >/dev/null 2>&1 && echo running || echo stopped')" "stopped"

echo
echo "C3. reload path with Postfix actually running"
in_c 'postfix start' >/dev/null
check "postfix started" "$(in_c 'postfix status >/dev/null 2>&1 && echo running || echo stopped')" "running"
docker exec "$CONTAINER" postconf -e 'smtpd_policy_service_timeout = 100s' >/dev/null
out="$(run_play)" || true
check "play succeeded" "$(failed_count "$out")" "0"
check "timeout restored"  "$(in_c 'postconf -h smtpd_policy_service_timeout')" "10s"
check "postfix still running" "$(in_c 'postfix status >/dev/null 2>&1 && echo running || echo stopped')" "running"

# --- D: config change restarts the agent ------------------------------------

echo
echo "D. config change restarts the agent"
write_play "        vspam_agent_log_level: debug
        vspam_agent_configure_postfix: true"
out="$(run_play)" || true
check "play succeeded" "$(failed_count "$out")" "0"
contains "new log level written" "$(in_c 'cat /etc/vspam/agent.yml')" "log_level: debug"
check "service still active" "$(in_c 'systemctl is-active vspam-agent')" "active"
contains "health still answers" "$(in_c 'curl -sS --max-time 5 http://127.0.0.1:10046/health')" "ok"
contains "previous config kept" "$(in_c 'ls /etc/vspam/')" "agent.yml."

# --- done -------------------------------------------------------------------

echo
echo "passed $pass, failed $fail"
[ "$fail" -eq 0 ]
