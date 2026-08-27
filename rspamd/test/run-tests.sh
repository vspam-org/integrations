#!/usr/bin/env bash
#
# Runs the vspam.org Rspamd module against a real Rspamd, with a mock standing
# in for the agent and the public API. Needs nothing but Docker.
#
#   ./run-tests.sh              full run
#   KEEP=1 ./run-tests.sh       leave the containers up afterwards for poking
#
# Three scenarios, each a config change plus an Rspamd restart:
#   A  agent answers            -> symbols come from the agent
#   B  agent refused, API up    -> symbols come from the hash lookup
#   C  both unreachable         -> VSPAM_FAIL, and the message still passes

set -euo pipefail

RSPAMD_IMAGE="${RSPAMD_IMAGE:-rspamd/rspamd:latest}"
# mailcow's Rspamd image has an entrypoint that blocks until the rest of the
# mailcow stack answers, so running the suite against your own deployment's
# image means bypassing it and supplying the arguments it would have passed:
#   RSPAMD_IMAGE=ghcr.io/mailcow/rspamd:4.1.4-1 \
#   RSPAMD_ENTRYPOINT=/usr/bin/rspamd \
#   RSPAMD_ARGS="-f -u _rspamd -g _rspamd" ./run-tests.sh
RSPAMD_ENTRYPOINT="${RSPAMD_ENTRYPOINT:-}"
RSPAMD_ARGS="${RSPAMD_ARGS:-}"
PYTHON_IMAGE="${PYTHON_IMAGE:-python:3-alpine}"
NET="vspam-rspamd-test"
MOCK="vspam-mock"
RSPAMD="vspam-rspamd"

HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d)"

pass=0
fail=0

cleanup() {
  if [ "${KEEP:-0}" != "1" ]; then
    docker rm -f "$RSPAMD" "$MOCK" >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
  else
    echo "KEEP=1: leaving $RSPAMD / $MOCK on network $NET, config in $WORK"
    return
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

# --- fixtures ---------------------------------------------------------------

mkdir -p "$WORK/local.d" "$WORK/msg"

cat >"$WORK/local.d/logging.inc" <<'EOF'
level = "info";
debug_modules = ["vspam"];
EOF

cp "$HERE/../local.d/groups.conf" "$WORK/local.d/groups.conf"

# A message whose envelope sender is on a given domain, with an optional link.
write_msg() {
  local file="$1" from_domain="$2" link="${3:-https://clean.example.org/hello}"
  cat >"$WORK/msg/$file" <<EOF
From: Sender <sender@$from_domain>
To: Recipient <rcpt@example.org>
Subject: vspam module test
Message-ID: <$file@$from_domain>
Date: Mon, 26 Aug 2026 12:00:00 +0000
Content-Type: text/plain; charset=us-ascii

Please look at $link
EOF
}

write_msg clean.eml clean.example.org
write_msg phishing-sender.eml phish.example.net
write_msg phishing-url.eml clean.example.org https://phish.example.net/login
write_msg malware-sender.eml malware.example.net
write_msg botnet-sender.eml botnet.example.net
write_msg spam-sender.eml spammy.example.net
write_msg tor-sender.eml tornode.example.net
write_msg unknowncat-sender.eml unknowncat.example.net
write_msg suspicious-sender.eml maybe.example.net
# Sender and link listed under different categories: phishing must win, once.
write_msg mixed.eml spammy.example.net https://phish.example.net/login

# --- helpers ----------------------------------------------------------------

write_config() {
  # $1 agent_url, $2 api_url
  cat >"$WORK/local.d/vspam.conf" <<EOF
agent_url = "$1";
api_url = "$2";
fallback_to_api = true;
agent_cooldown = 0;
timeout = 2.0;
check_local = true;
check_authed = true;
EOF
}

start_rspamd() {
  docker rm -f "$RSPAMD" >/dev/null 2>&1 || true
  local entry=()
  [ -n "$RSPAMD_ENTRYPOINT" ] && entry=(--entrypoint "$RSPAMD_ENTRYPOINT")

  docker run -d --name "$RSPAMD" --network "$NET" \
    "${entry[@]+"${entry[@]}"}" \
    -e RSPAMD_LOG_TYPE=console \
    -v "$HERE/../vspam.lua:/etc/rspamd/plugins.d/vspam.lua:ro" \
    -v "$HERE/../rspamd.conf.local:/etc/rspamd/rspamd.conf.local:ro" \
    -v "$WORK/local.d:/etc/rspamd/local.d:ro" \
    -v "$WORK/msg:/msg:ro" \
    "$RSPAMD_IMAGE" $RSPAMD_ARGS >/dev/null

  for _ in $(seq 1 60); do
    if docker exec "$RSPAMD" rspamc -h localhost:11333 symbols /msg/clean.eml \
      >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.5
  done
  echo "rspamd did not come up; last log lines:" >&2
  docker logs --tail 30 "$RSPAMD" >&2
  return 1
}

# scan <message> [client-ip] -> rspamc symbols output
scan() {
  local msg="$1" ip="${2:-203.0.113.5}"
  docker exec "$RSPAMD" rspamc -h localhost:11333 --ip "$ip" symbols "/msg/$msg" 2>&1
}

check() {
  # check <name> <output> <expected-symbol|-> [forbidden-symbol]
  local name="$1" out="$2" want="$3" forbid="${4:-}"
  local ok=1

  if [ "$want" != "-" ] && ! grep -q "^Symbol: $want" <<<"$out"; then
    ok=0
  fi
  if [ -n "$forbid" ] && grep -q "^Symbol: $forbid" <<<"$out"; then
    ok=0
  fi

  if [ "$ok" = 1 ]; then
    printf '  ok   %s\n' "$name"
    pass=$((pass + 1))
  else
    printf '  FAIL %s (wanted %s%s)\n' "$name" "$want" \
      "${forbid:+, forbidding $forbid}"
    grep '^Symbol: VSPAM' <<<"$out" | sed 's/^/       /' || echo "       (no VSPAM symbols)"
    fail=$((fail + 1))
  fi
}

# weight_of <output> <symbol> -> the numeric weight rspamc reported
weight_of() {
  grep "^Symbol: $2 " <<<"$1" | sed -n 's/.*(\([-0-9.]*\)).*/\1/p' | head -1 || true
}

# --- setup ------------------------------------------------------------------

docker network rm "$NET" >/dev/null 2>&1 || true
docker network create "$NET" >/dev/null

docker rm -f "$MOCK" >/dev/null 2>&1 || true
docker run -d --name "$MOCK" --network "$NET" \
  -v "$HERE/mock-vspam-server.py:/mock.py:ro" \
  "$PYTHON_IMAGE" python3 /mock.py 10046 >/dev/null

for _ in $(seq 1 30); do
  if docker run --rm --network "$NET" "$PYTHON_IMAGE" \
    python3 -c "import urllib.request,sys; urllib.request.urlopen('http://$MOCK:10046/health')" \
    >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done

# --- scenario A: agent answers ---------------------------------------------

echo "configtest"
write_config "http://$MOCK:10046" "http://$MOCK:10046"
start_rspamd
out="$(docker exec "$RSPAMD" rspamadm configtest 2>&1)"
if grep -q "syntax OK" <<<"$out"; then
  printf '  ok   rspamadm configtest\n'
  pass=$((pass + 1))
else
  printf '  FAIL rspamadm configtest\n%s\n' "$out"
  fail=$((fail + 1))
fi

echo "scenario A: agent reachable"
check "clean message gets no vspam symbol"   "$(scan clean.eml)"              - VSPAM_
check "phishing sender"                      "$(scan phishing-sender.eml)"    VSPAM_PHISHING
check "phishing URL in body"                 "$(scan phishing-url.eml)"       VSPAM_PHISHING
check "malware sender"                       "$(scan malware-sender.eml)"     VSPAM_MALWARE
check "botnet sender"                        "$(scan botnet-sender.eml)"      VSPAM_BOTNET
check "spam sender"                          "$(scan spam-sender.eml)"        VSPAM_SPAM
check "tor sender"                           "$(scan tor-sender.eml)"         VSPAM_TOR
check "unknown category folds to threat"     "$(scan unknowncat-sender.eml)"  VSPAM_THREAT
check "scored but unlisted is suspicious"    "$(scan suspicious-sender.eml)"  VSPAM_SUSPICIOUS VSPAM_PHISHING
check "listed IP via client_ip"              "$(scan clean.eml 203.0.113.66)" VSPAM_SPAM
check "agent path never reports failure"     "$(scan phishing-sender.eml)"    - VSPAM_FAIL

a_out="$(scan phishing-sender.eml)"
w="$(weight_of "$a_out" VSPAM_PHISHING)"
if [ "$w" = "6.00" ]; then
  printf '  ok   phishing weight is 6.00\n'; pass=$((pass + 1))
else
  printf '  FAIL phishing weight was %s, wanted 6.00\n' "${w:-none}"; fail=$((fail + 1))
fi

# Sender and link both listed, under different categories. The agent answers
# with the first listing it finds walking sender -> IP -> URL, so the sender's
# category is the one reported. One symbol either way, never both.
m_out="$(scan mixed.eml)"
check "agent reports the first listed indicator" "$m_out" VSPAM_SPAM VSPAM_PHISHING
w="$(weight_of "$m_out" VSPAM_SPAM)"
if [ "$w" = "3.00" ]; then
  printf '  ok   two listings are not double counted\n'; pass=$((pass + 1))
else
  printf '  FAIL mixed message weight was %s, wanted 3.00\n' "${w:-none}"; fail=$((fail + 1))
fi

# --- scenario B: agent gone, API up ----------------------------------------

echo "scenario B: agent refused, public API reachable"
write_config "http://127.0.0.1:9" "http://$MOCK:10046"
start_rspamd
check "falls back to the hash lookup"        "$(scan malware-sender.eml)"     VSPAM_MALWARE VSPAM_FAIL
check "fallback still classifies phishing"   "$(scan phishing-url.eml)"       VSPAM_PHISHING
check "fallback keeps a clean message clean" "$(scan clean.eml)"              - VSPAM_
check "fallback carries the suspicious verdict" "$(scan suspicious-sender.eml)" VSPAM_SUSPICIOUS

# The fallback checks every indicator independently rather than stopping at
# the first hit, so here the stronger category wins -- and still only one
# symbol is inserted.
b_out="$(scan mixed.eml)"
check "fallback reports the stronger category" "$b_out" VSPAM_PHISHING VSPAM_SPAM
w="$(weight_of "$b_out" VSPAM_PHISHING)"
if [ "$w" = "6.00" ]; then
  printf '  ok   fallback does not double count either\n'; pass=$((pass + 1))
else
  printf '  FAIL fallback mixed weight was %s, wanted 6.00\n' "${w:-none}"; fail=$((fail + 1))
fi

# --- scenario C: nothing reachable ------------------------------------------

echo "scenario C: agent and API both unreachable"
write_config "http://127.0.0.1:9" "http://127.0.0.1:9"
start_rspamd
c_out="$(scan phishing-sender.eml)"
check "reports the failure"                  "$c_out" VSPAM_FAIL VSPAM_PHISHING
w="$(weight_of "$c_out" VSPAM_FAIL)"
if [ "$w" = "0.00" ]; then
  printf '  ok   failure carries no weight\n'; pass=$((pass + 1))
else
  printf '  FAIL VSPAM_FAIL weight was %s, wanted 0.00\n' "${w:-none}"; fail=$((fail + 1))
fi
if grep -q '^Action: reject' <<<"$c_out"; then
  printf '  FAIL message was rejected with both lookups down\n%s\n' "$c_out"; fail=$((fail + 1))
else
  printf '  ok   message still passes when both are down\n'; pass=$((pass + 1))
fi

# --- result -----------------------------------------------------------------

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
