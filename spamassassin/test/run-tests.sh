#!/usr/bin/env bash
#
# Runs the vspam.org SpamAssassin rules against a real SpamAssassin, with
# CoreDNS standing in for dnsbl.vspam.org. Needs nothing but Docker.
#
#   ./run-tests.sh              lint + rule behaviour
#   ./run-tests.sh --channel    also publish a channel and sa-update from it
#   KEEP=1 ./run-tests.sh       leave the containers up afterwards
#
# The channel phase is the real thing: it builds the tarball with
# publish-sa-update-channel.sh, signs it with a throwaway GPG key, serves it
# over HTTP, answers the DNS records sa-update looks for, and runs the client.

set -euo pipefail

SA_IMAGE="vspam-sa-test"
COREDNS_IMAGE="${COREDNS_IMAGE:-coredns/coredns:latest}"
PYTHON_IMAGE="${PYTHON_IMAGE:-python:3-alpine}"
NET="vspam-sa-test"
DNS="vspam-sa-dns"
SA="vspam-sa"
MIRROR="vspam-sa-mirror"

# Fixed so every DNS record is known before CoreDNS starts; it reads its zone
# files once, at startup.
CHANNEL_SERIAL=2026082601

HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d)"
WITH_CHANNEL=0
[ "${1:-}" = "--channel" ] && WITH_CHANNEL=1

pass=0
fail=0

cleanup() {
  if [ "${KEEP:-0}" = "1" ]; then
    echo "KEEP=1: leaving containers on network $NET, work dir $WORK"
    return
  fi
  docker rm -f "$SA" "$DNS" "$MIRROR" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

ok()  { printf '  ok   %s\n' "$1"; pass=$((pass + 1)); }
bad() { printf '  FAIL %s\n' "$1"; fail=$((fail + 1)); }

# --- messages ---------------------------------------------------------------

mkdir -p "$WORK/msg" "$WORK/zones" "$WORK/etc" "$WORK/pub"

# write_msg <file> <envelope-sender-domain> <From-domain> <client-ip> <link>
write_msg() {
  cat >"$WORK/msg/$1" <<EOF
Return-Path: <bounce@$2>
Received: from mail.$3 (mail.$3 [$4])
	by mx.example.org (Postfix) with ESMTP id ABC$RANDOM
	for <rcpt@example.org>; Mon, 26 Aug 2026 12:00:00 +0000
From: Sender <sender@$3>
To: Recipient <rcpt@example.org>
Subject: vspam rule test
Message-ID: <$1@$3>
Date: Mon, 26 Aug 2026 12:00:00 +0000
Content-Type: text/plain; charset=us-ascii

Please have a look at $5
EOF
}

CLEAN_LINK="https://clean.example.org/hello"
write_msg clean.eml         clean.example.org   clean.example.org   198.51.100.7 "$CLEAN_LINK"
write_msg ip-spam.eml       clean.example.org   clean.example.org   203.0.113.66 "$CLEAN_LINK"
write_msg ip-phish.eml      clean.example.org   clean.example.org   203.0.113.2  "$CLEAN_LINK"
write_msg env-malware.eml   malware.example.net clean.example.org   198.51.100.7 "$CLEAN_LINK"
write_msg hdr-botnet.eml    clean.example.org   botnet.example.net  198.51.100.7 "$CLEAN_LINK"
write_msg tor.eml           clean.example.org   tornode.example.net 198.51.100.7 "$CLEAN_LINK"
write_msg weird.eml         clean.example.org   weird.example.net   198.51.100.7 "$CLEAN_LINK"
write_msg uri-phish.eml     clean.example.org   clean.example.org   198.51.100.7 "https://phish.example.net/login"
write_msg uri-notrim.eml    clean.example.org   clean.example.org   198.51.100.7 "https://evil-user.shared.example.net/login"
write_msg uri-trimguard.eml clean.example.org   clean.example.org   198.51.100.7 "https://shared.example.net/index"
write_msg both.eml          phish.example.net   phish.example.net   198.51.100.7 "https://phish.example.net/login"

# --- setup ------------------------------------------------------------------

echo "building the test image (cached after the first run)"
docker build -q -t "$SA_IMAGE" "$HERE" >/dev/null

docker network rm "$NET" >/dev/null 2>&1 || true
docker network create "$NET" >/dev/null

cp "$HERE/dnsbl-zone-fixture.zone" "$WORK/zones/"

# The channel mirror, started before CoreDNS because its address has to go
# into the zone.
docker rm -f "$MIRROR" >/dev/null 2>&1 || true
docker run -d --name "$MIRROR" --network "$NET" -w /pub \
  -v "$WORK/pub:/pub:ro" "$PYTHON_IMAGE" python3 -m http.server 80 >/dev/null
MIRROR_IP="$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}" "$MIRROR")"

# sa-update asks for its own version reversed (4.0.1 -> 1.0.4), so the zone
# has to name the version actually in the image rather than a guess.
SA_VERSION="$(docker run --rm "$SA_IMAGE" perl -MMail::SpamAssassin \
  -e 'my $v = $Mail::SpamAssassin::VERSION;
      $v =~ /^(\d+)\.(\d{3})(\d{3})$/ and $v = join(".", $1+0, $2+0, $3+0);
      print $v')"
SA_VERSION_REV="$(echo "$SA_VERSION" | awk -F. '{ for (i = NF; i > 0; i--) printf "%s%s", $i, (i > 1 ? "." : "\n") }')"

cat >"$WORK/zones/Corefile" <<'EOF'
dnsbl.vspam.org:53 {
    file /zones/dnsbl-zone-fixture.zone
    errors
}
updates.vspam.test:53 {
    file /zones/updates.vspam.test.zone
    errors
}
vspam.test:53 {
    file /zones/vspam.test.zone
    errors
}
.:53 {
    template ANY ANY {
        rcode NXDOMAIN
    }
    errors
}
EOF

cat >"$WORK/zones/updates.vspam.test.zone" <<ZONE
\$ORIGIN updates.vspam.test.
\$TTL 60
@  IN SOA ns.updates.vspam.test. hostmaster.updates.vspam.test. ( 1 60 60 60 60 )
@  IN NS  ns.updates.vspam.test.
ns IN A   127.0.0.1
$SA_VERSION_REV IN TXT "$CHANNEL_SERIAL"
mirrors IN TXT "http://mirror.vspam.test/MIRRORED.BY"
ZONE

cat >"$WORK/zones/vspam.test.zone" <<ZONE
\$ORIGIN vspam.test.
\$TTL 60
@      IN SOA ns.vspam.test. hostmaster.vspam.test. ( 1 60 60 60 60 )
@      IN NS  ns.vspam.test.
ns     IN A   127.0.0.1
mirror IN A   $MIRROR_IP
ZONE

docker rm -f "$DNS" >/dev/null 2>&1 || true
docker run -d --name "$DNS" --network "$NET" \
  -v "$WORK/zones:/zones:ro" "$COREDNS_IMAGE" -conf /zones/Corefile >/dev/null
sleep 2
DNS_IP="$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}" "$DNS")"

cat >"$WORK/etc/vspam-test.cf" <<EOF
# Test-only: point every lookup at the CoreDNS fixture and stop SpamAssassin
# probing the real world to decide whether DNS works.
dns_server $DNS_IP
dns_available yes

# The fixtures use RFC 2606 domains, which SpamAssassin ships in its URI skip
# list precisely because they are reserved. Un-skip them here so the URI rules
# are actually exercised. Nothing outside this test needs it.
clear_uridnsbl_skip_domain example.com example.net example.org
EOF
cp "$HERE/../20_vspam.cf" "$WORK/etc/20_vspam.cf"

docker rm -f "$SA" >/dev/null 2>&1 || true
docker run -d --name "$SA" --network "$NET" --dns "$DNS_IP" \
  -v "$WORK/msg:/msg:ro" \
  -v "$HERE/..:/src:ro" \
  -v "$WORK/pub:/pub" \
  -v "$WORK/etc/20_vspam.cf:/etc/spamassassin/20_vspam.cf:ro" \
  -v "$WORK/etc/vspam-test.cf:/etc/spamassassin/99_vspam_test.cf:ro" \
  "$SA_IMAGE" >/dev/null

# --- lint -------------------------------------------------------------------

echo "lint"
if docker exec "$SA" spamassassin --lint >"$WORK/lint.out" 2>&1; then
  ok "spamassassin --lint"
else
  bad "spamassassin --lint"
  sed 's/^/       /' "$WORK/lint.out"
fi

# --- rule behaviour ---------------------------------------------------------

# The scored VSPAM_ rules that fired, one per line. `spamassassin -t` prints
# the analysis table twice -- once for the rewritten message and once for the
# attached original -- so only the first block is read, otherwise every rule
# would look like it fired twice.
fired() {
  docker exec "$SA" sh -c "spamassassin -t < /msg/$1 2>/dev/null" \
    | awk '/^Content analysis details/ {n++} n == 1' \
    | grep -E '^ *[-0-9.]+ +VSPAM_' | awk '{print $2}' | sort || true
}

# expect <name> <message> <rule|-> [forbidden-rule]
expect() {
  local name="$1" msg="$2" want="$3" forbid="${4:-}"
  local got good=1
  got="$(fired "$msg")"

  if [ "$want" != "-" ] && ! grep -qx "$want" <<<"$got"; then good=0; fi
  if [ "$want" = "-" ] && [ -n "$got" ]; then good=0; fi
  if [ -n "$forbid" ] && grep -qx "$forbid" <<<"$got"; then good=0; fi

  if [ "$good" = 1 ]; then
    ok "$name"
  else
    bad "$name (wanted ${want}${forbid:+, forbidding $forbid}; got: ${got:-none})"
  fi
}

echo "rules"
expect "clean message fires nothing"          clean.eml           -
expect "connecting IP, spam"                  ip-spam.eml         VSPAM_SPAM
expect "connecting IP, phishing"              ip-phish.eml        VSPAM_PHISHING
expect "envelope sender, malware"             env-malware.eml     VSPAM_MALWARE
expect "From header domain, botnet"           hdr-botnet.eml      VSPAM_BOTNET
expect "tor is context, not a verdict"        tor.eml             VSPAM_TOR VSPAM_SPAM
expect "unlisted return code folds to threat" weird.eml           VSPAM_THREAT
expect "URI in the body, phishing"            uri-phish.eml       VSPAM_PHISHING
expect "exact host below a shared domain"     uri-notrim.eml      VSPAM_PHISHING
expect "the shared domain itself is clean"    uri-trimguard.eml   -
expect "sender and URI together"              both.eml            VSPAM_SENDER_AND_URI

# One listing, one score: the phishing meta must not stack with itself when
# the sender domain and a URI are both listed as phishing.
n="$(fired both.eml | grep -cx VSPAM_PHISHING || true)"
if [ "$n" = "1" ]; then
  ok "a category scores once however many surfaces saw it"
else
  bad "VSPAM_PHISHING fired $n times on both.eml, wanted 1"
fi

w="$(docker exec "$SA" sh -c "spamassassin -t < /msg/uri-phish.eml 2>/dev/null" \
  | grep -E '^ *[-0-9.]+ +VSPAM_PHISHING' | awk '{print $1}' | head -1 || true)"
if [ "$w" = "2.0" ]; then
  ok "phishing weight is 2.0"
else
  bad "phishing weight was ${w:-none}, wanted 2.0"
fi

# --- sa-update channel ------------------------------------------------------

if [ "$WITH_CHANNEL" = 1 ]; then
  echo "sa-update channel (SpamAssassin $SA_VERSION asks for $SA_VERSION_REV.updates.vspam.test)"

  # A throwaway signing key, generated in the container. The point is to prove
  # sa-update's signature check is satisfied by what the publisher produces,
  # not to test GnuPG.
  docker exec "$SA" sh -c 'gpg --batch --passphrase "" --quick-generate-key \
    "vspam.org channel test <test@vspam.test>" default default never' \
    >"$WORK/gpg.out" 2>&1 || true
  KEY_ID="$(docker exec "$SA" sh -c \
    "gpg --list-secret-keys --with-colons 2>/dev/null | awk -F: '/^fpr:/ {print \$10; exit}'" || true)"

  if [ -z "$KEY_ID" ]; then
    bad "generate a signing key"
    sed 's/^/       /' "$WORK/gpg.out"
  else
    ok "generate a signing key"

    if docker exec "$SA" sh -c "/src/publish-sa-update-channel.sh \
        --channel updates.vspam.test \
        --mirror http://mirror.vspam.test/ \
        --serial $CHANNEL_SERIAL \
        --sa-versions '$SA_VERSION' \
        --gpg-key $KEY_ID /pub" >"$WORK/publish.out" 2>&1; then
      ok "publish-sa-update-channel.sh builds the channel"
    else
      bad "publish-sa-update-channel.sh builds the channel"
      sed 's/^/       /' "$WORK/publish.out"
    fi

    for f in "$CHANNEL_SERIAL.tar.gz" "$CHANNEL_SERIAL.tar.gz.sha512" \
             "$CHANNEL_SERIAL.tar.gz.asc" MIRRORED.BY GPG.KEY; do
      if [ -s "$WORK/pub/$f" ]; then ok "published $f"; else bad "published $f"; fi
    done

    if docker exec "$SA" sh -c 'sa-update --import /pub/GPG.KEY' \
      >"$WORK/import.out" 2>&1; then
      ok "sa-update --import accepts the key"
    else
      bad "sa-update --import accepts the key"
      sed 's/^/       /' "$WORK/import.out"
    fi

    # The real client run: DNS discovery, mirror list, download, sha512,
    # signature, sa-update's own lint of the extracted rules, install.
    if docker exec "$SA" sh -c "rm -rf /tmp/upd && mkdir -p /tmp/upd && \
        sa-update -v --updatedir /tmp/upd \
          --channel updates.vspam.test --gpgkey $KEY_ID" \
        >"$WORK/update.out" 2>&1; then
      ok "sa-update installs the channel"
    else
      bad "sa-update installs the channel"
      tail -25 "$WORK/update.out" | sed 's/^/       /'
    fi

    if docker exec "$SA" sh -c 'test -s /tmp/upd/updates_vspam_test/20_vspam.cf'; then
      ok "the rules landed in the update directory"
    else
      bad "the rules landed in the update directory"
      docker exec "$SA" sh -c 'find /tmp/upd -type f' | sed 's/^/       /'
    fi

    # A tampered tarball must be refused. Fresh update dir, so the client does
    # not simply consider itself up to date and skip the download. A client
    # with GPG enabled never fetches the checksum files, so the detached
    # signature is what has to catch this.
    printf 'corrupted\n' >>"$WORK/pub/$CHANNEL_SERIAL.tar.gz"
    if docker exec "$SA" sh -c "rm -rf /tmp/upd2 && mkdir -p /tmp/upd2 && \
        sa-update -v --updatedir /tmp/upd2 \
          --channel updates.vspam.test --gpgkey $KEY_ID" \
        >"$WORK/tamper.out" 2>&1; then
      bad "a tampered tarball is rejected (sa-update accepted it)"
    elif grep -q 'GPG validation failed' "$WORK/tamper.out"; then
      ok "a tampered tarball fails signature verification"
    else
      bad "a tampered tarball was rejected, but not by the signature check"
      tail -10 "$WORK/tamper.out" | sed 's/^/       /'
    fi
  fi
fi

# --- result -----------------------------------------------------------------

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
