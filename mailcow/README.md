# vspam.org on mailcow-dockerized

Three independent paths. Start with the DNSBL — it needs no account, no agent,
and no container, and you can have it running in about a minute.

| | DNSBL only | DNSBL + agent | Rspamd module |
|---|---|---|---|
| API key needed | no | free key | optional |
| Extra container | no | one, ~4 MB | optional |
| Local caching | resolver's | BoltDB, 10 min TTL | BoltDB, with the agent |
| Checks the sender and connecting IP | yes | yes | yes |
| **Checks links in the message body** | no | no | **yes** |
| **Suspicious-but-not-listed verdict** | no | no | **yes** |
| Reports what this server sees | no | yes | yes, with the agent |
| Setup | 2 files | 3 files | 3 files |

Paths 1 and 3 read the same data and must not be run together without the
de-duplication drop-in — see [Running both](#running-both).

---

## Path 1 — DNSBL only (~60 seconds)

From your `mailcow-dockerized` directory:

```bash
curl -fsSL https://raw.githubusercontent.com/vspam-org/vspam.org/main/integrations/mailcow/rspamd/vspam.conf \
  -o data/conf/rspamd/local.d/rbl.conf
curl -fsSL https://raw.githubusercontent.com/vspam-org/vspam.org/main/integrations/mailcow/scores.conf \
  -o data/conf/rspamd/local.d/groups.conf

docker compose restart rspamd-mailcow
```

**If either file already exists, merge instead of overwriting** — mailcow ships
its own entries in both, and replacing them will drop RBLs you are relying on.

Verify:

```bash
docker compose exec rspamd-mailcow rspamadm configtest
```

Then send yourself a test message and look for `RBL_VSPAM_*` in the Rspamd
history at `https://your-mailcow/rspamd/`.

### Start at zero weight

Set every weight in `groups.conf` to `0.0` for the first week. Symbols still
appear in history so you can see what would have happened, without affecting
delivery. Raise them once you have looked at a week of real mail.

## Path 2 — add the agent

Adds a local cache and sends what this server observes back to the pool, which
is what makes the list useful to the next operator.

1. Get a free key at <https://vspam.org/account>.
2. Add to `mailcow.conf`:
   ```
   VSPAM_API_KEY=vspam_your_key_here
   ```
3. Copy `docker-compose.override.yml` from this directory into your
   `mailcow-dockerized` directory — **merging** if you already have one.
4. ```bash
   docker compose up -d
   ```

Verify the agent is answering:

```bash
docker compose exec rspamd-mailcow \
  curl -s "http://vspam-agent:10046/check?sender_domain=example.com&client_ip=1.2.3.4"
# {"malicious":false,"action":"allow"}
```

Keep the DNSBL config from Path 1 in place. Rspamd continues to score from DNS;
the agent runs alongside it for caching and reporting.

## Path 3 — the Rspamd module

Replaces the DNS lookups with a native module. It checks links in the message
body, which the DNSBL cannot do at all, and carries vspam.org's
suspicious-but-not-listed verdict, which a DNS return code has no way to
express. Full description: [`../rspamd/README.md`](../rspamd/README.md).

mailcow mounts everything this needs already.

```bash
curl -fsSL https://raw.githubusercontent.com/vspam-org/vspam.org/main/integrations/rspamd/vspam.lua \
  -o data/conf/rspamd/plugins.d/vspam.lua

# Append — this file is shared with anything else you have configured.
curl -fsSL https://raw.githubusercontent.com/vspam-org/vspam.org/main/integrations/rspamd/rspamd.conf.local \
  >> data/conf/rspamd/rspamd.conf.local

cat > data/conf/rspamd/local.d/vspam.conf <<'EOF'
# Rspamd and the agent are separate containers here, so reach it by the
# service alias the override file sets rather than on localhost.
agent_url = "http://vspam-agent:10046";
fallback_to_api = true;
EOF

docker compose exec rspamd-mailcow rspamadm configtest
docker compose restart rspamd-mailcow
```

Weights are built into the module. To change them, take
`../rspamd/local.d/groups.conf` and **merge** it into
`data/conf/rspamd/local.d/groups.conf` — and set them all to `0.0` for the
first week, as above.

Without Path 2 the module falls back to the public API, sending only a SHA-256
of each indicator. That works, but it is slower than a local cache and reports
nothing back, so pair it with the agent once you are happy with it.

### Running both

Path 1 and Path 3 read the same listings, so running both scores every hit
twice. Pick one. If you want both anyway — say you already had the DNSBL and
are trying the module beside it — merge
`../rspamd/local.d/composites.conf` into
`data/conf/rspamd/local.d/composites.conf`, which collapses each duplicated
pair back to a single weight while leaving both symbols visible in the history.

### Tested against

The module's test suite passes against mailcow's own Rspamd image
(`ghcr.io/mailcow/rspamd:4.1.4-1`), covering each symbol, the API fallback, and
fail-open behaviour when nothing is reachable. To run it against the image your
deployment actually uses:

```bash
cd integrations/rspamd/test
RSPAMD_IMAGE=ghcr.io/mailcow/rspamd:4.1.4-1 \
RSPAMD_ENTRYPOINT=/usr/bin/rspamd \
RSPAMD_ARGS="-f -u _rspamd -g _rspamd" ./run-tests.sh
```

## Removing it

```bash
rm -f data/conf/rspamd/local.d/rbl.conf data/conf/rspamd/local.d/groups.conf
rm -f data/conf/rspamd/plugins.d/vspam.lua data/conf/rspamd/local.d/vspam.conf
# and drop the vspam { } block from data/conf/rspamd/rspamd.conf.local
# and the vspam-agent block from docker-compose.override.yml
docker compose up -d && docker compose restart rspamd-mailcow
```

Nothing else in mailcow is modified, so this reverts cleanly.

## False positives

Delist requests are reviewed by a human within 48 hours, need no account, and
are tracked publicly by ID: <https://vspam.org/delist>. Approval removes the
DNSBL publication and marks the report a false positive in our scoring history.

Check what we currently hold on a host before filing: <https://vspam.org/lookup>.

## Notes

- The agent's ports are not published to the host. Only containers on
  `mailcow-network` can reach it.
- The cache is a named volume. A bind mount will not work: the image runs as
  uid 65532 and a host directory arrives root-owned.
- Prefix-watch and ASN surfaces are context, not enforcement. Neither is
  published to the DNSBL zone used above.
