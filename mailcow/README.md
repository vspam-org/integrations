# vspam.org on mailcow-dockerized

Two independent paths. Start with the DNSBL — it needs no account, no agent, and
no container, and you can have it running in about a minute.

| | DNSBL only | DNSBL + agent |
|---|---|---|
| API key needed | no | free key |
| Extra container | no | one, ~4 MB |
| Local caching | resolver's | BoltDB, 10 min TTL |
| Reports what this server sees | no | yes |
| Setup | 2 files | 3 files |

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

## Removing it

```bash
rm data/conf/rspamd/local.d/rbl.conf data/conf/rspamd/local.d/groups.conf
# and drop the vspam-agent block from docker-compose.override.yml
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
