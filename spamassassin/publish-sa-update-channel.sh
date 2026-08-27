#!/usr/bin/env bash
#
# Builds an sa-update channel from 20_vspam.cf: the tarball an sa-update
# client downloads, its checksums, a detached GPG signature, the MIRRORED.BY
# file, and the DNS records that tell clients a new serial exists.
#
#   ./publish-sa-update-channel.sh --gpg-key 1A2B3C4D ./out
#
# Then upload the contents of ./out to the mirror and publish the TXT records
# printed at the end. Nothing here talks to the network or to DNS; publishing
# is deliberately a separate, reviewable step.
#
# What sa-update does with all this, in order:
#   1. TXT <reversed-SA-version>.<channel>   -> the serial to fetch
#   2. TXT mirrors.<channel>                 -> URL of the MIRRORED.BY file
#   3. GET <mirror>/<serial>.tar.gz and its signature
#   4. verifies the signature against a key the operator imported
#   5. extracts, runs its own --lint, and only then installs
#
# A client with GPG enabled -- the default, and the only sane way to run this
# -- fetches the .asc and never looks at the checksum files. The .sha512 and
# .sha256 are published for clients run with --no-gpg and for anyone
# verifying a download by hand; they are not what protects a normal client.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"

RULES="$HERE/20_vspam.cf"
CHANNEL="updates.vspam.org"
MIRROR="https://updates.vspam.org/"
SERIAL=""
GPG_KEY=""
GPG_HOMEDIR=""
SIGN=1

# SpamAssassin versions this channel serves. sa-update asks for its own
# version reversed, so each one needs its own TXT record even though they all
# point at the same tarball. Add a version here when you start supporting it.
SA_VERSIONS="3.4.4 3.4.5 3.4.6 4.0.0 4.0.1"

usage() {
  sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
  cat <<EOF

Options:
  --rules FILE        rule file to publish (default: $RULES)
  --channel NAME      channel hostname (default: $CHANNEL)
  --mirror URL        base URL clients download from (default: $MIRROR)
  --serial N          update serial; must increase (default: date +%Y%m%d%H)
  --sa-versions "A B" SpamAssassin versions to advertise
                      (default: $SA_VERSIONS)
  --gpg-key ID        key to sign with; clients pass this to --gpgkey
  --gpg-homedir DIR   GnuPG home to sign from
  --no-sign           skip signing. Testing only: sa-update refuses an
                      unsigned channel unless the client passes --no-gpg,
                      which nobody should be asked to do.
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --rules)        RULES="$2"; shift 2 ;;
    --channel)      CHANNEL="$2"; shift 2 ;;
    --mirror)       MIRROR="$2"; shift 2 ;;
    --serial)       SERIAL="$2"; shift 2 ;;
    --sa-versions)  SA_VERSIONS="$2"; shift 2 ;;
    --gpg-key)      GPG_KEY="$2"; shift 2 ;;
    --gpg-homedir)  GPG_HOMEDIR="$2"; shift 2 ;;
    --no-sign)      SIGN=0; shift ;;
    -h|--help)      usage; exit 0 ;;
    -*)             echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
    *)              OUT="$1"; shift ;;
  esac
done

if [ -z "${OUT:-}" ]; then
  echo "error: no output directory given" >&2
  usage >&2
  exit 2
fi
if [ ! -f "$RULES" ]; then
  echo "error: rule file not found: $RULES" >&2
  exit 2
fi
if [ "$SIGN" = 1 ] && [ -z "$GPG_KEY" ]; then
  echo "error: --gpg-key is required (or --no-sign, for testing only)" >&2
  exit 2
fi

# A serial only has to increase; sa-update compares it numerically against
# what the client already has. Date-based keeps it monotonic and readable.
[ -n "$SERIAL" ] || SERIAL="$(date -u +%Y%m%d%H)"
case "$SERIAL" in
  ''|*[!0-9]*) echo "error: serial must be digits only: $SERIAL" >&2; exit 2 ;;
esac

MIRROR="${MIRROR%/}"

mkdir -p "$OUT"
# Absolute, because the tarball is written from inside the staging directory.
OUT="$(cd "$OUT" && pwd)"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

# The tarball holds the rule files at its root; sa-update extracts it into a
# directory of its own and lints that directory before installing.
cp "$RULES" "$STAGE/$(basename "$RULES")"

TARBALL="$OUT/$SERIAL.tar.gz"
# Name the members explicitly rather than archiving ".": sa-update extracts
# each entry by hand and fails on the "./" directory entry that `tar -C dir .`
# writes first.
( cd "$STAGE" && tar -czf "$TARBALL" -- * )

# For --no-gpg clients and for hand verification. sa-update reads the first hex
# token out of the file, which is what the standard tools emit.
( cd "$OUT" && sha512sum "$SERIAL.tar.gz" > "$SERIAL.tar.gz.sha512" )
( cd "$OUT" && sha256sum "$SERIAL.tar.gz" > "$SERIAL.tar.gz.sha256" )

GPG_ARGS=()
[ -n "$GPG_HOMEDIR" ] && GPG_ARGS+=(--homedir "$GPG_HOMEDIR")

if [ "$SIGN" = 1 ]; then
  rm -f "$TARBALL.asc"
  gpg "${GPG_ARGS[@]}" --batch --yes --armor --local-user "$GPG_KEY" \
    --detach-sign --output "$TARBALL.asc" "$TARBALL"
  gpg "${GPG_ARGS[@]}" --batch --yes --armor --export "$GPG_KEY" > "$OUT/GPG.KEY"
else
  echo "warning: not signing; sa-update clients will reject this channel" >&2
fi

cat >"$OUT/MIRRORED.BY" <<EOF
# Mirrors for the vspam.org SpamAssassin channel.
# One base URL per line. sa-update picks one and fetches <serial>.tar.gz and
# its detached signature from it.
$MIRROR/
EOF

# Reverse the version for the DNS name: sa-update asks for 1.0.4.<channel>
# when it is version 4.0.1.
reverse_version() {
  echo "$1" | awk -F. '{ for (i = NF; i > 0; i--) printf "%s%s", $i, (i > 1 ? "." : "\n") }'
}

RECORDS="$OUT/dns-records.txt"
{
  echo "; TXT records for the sa-update channel $CHANNEL"
  echo "; Serial $SERIAL, generated $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo ";"
  echo "; One version record per supported SpamAssassin release: a client asks"
  echo "; for its own version reversed, and reads the serial out of the answer."
  for v in $SA_VERSIONS; do
    printf '%s.%s. 300 IN TXT "%s"\n' "$(reverse_version "$v")" "$CHANNEL" "$SERIAL"
  done
  echo ";"
  echo "; Where to find the mirror list."
  printf 'mirrors.%s. 300 IN TXT "%s/MIRRORED.BY"\n' "$CHANNEL" "$MIRROR"
} >"$RECORDS"

cat <<EOF

Built serial $SERIAL in $OUT

  $(basename "$TARBALL")
  $(basename "$TARBALL").sha512
  $(basename "$TARBALL").sha256$([ "$SIGN" = 1 ] && printf '\n  %s.asc\n  GPG.KEY' "$(basename "$TARBALL")")
  MIRRORED.BY
  dns-records.txt

Next:
  1. Upload everything except dns-records.txt to $MIRROR/
  2. Publish the TXT records in dns-records.txt
  3. Clients subscribe with:
       sa-update --channel $CHANNEL$([ "$SIGN" = 1 ] && printf ' --gpgkey %s' "$GPG_KEY")

Publish the records only after the files are reachable. A client that reads a
new serial and cannot fetch it treats the channel as failed.
EOF
