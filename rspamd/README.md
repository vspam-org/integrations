# vspam.org for Rspamd

A native Rspamd module. It checks the envelope sender's domain, the connecting
IP and every URL in the body against vspam.org, and inserts one weighted symbol
per message describing what was found.

There is also a DNSBL-only path that needs no module at all — see
[Which path](#which-path) below.

## What you get that the DNSBL cannot give you

| | DNSBL (`local.d/rbl.conf`) | This module |
|---|---|---|
| Sender domain, connecting IP | yes | yes |
| **URLs in the message body** | no | yes |
| Separate symbol per category | yes | yes |
| **Suspicious-but-not-listed verdict** | no | `VSPAM_SUSPICIOUS` |
| **Reports what this server saw** | no | yes, with the agent |
| Local caching | your resolver's | BoltDB, with the agent |
| Lookups leave the machine | in DNS, in clear | hashed, or not at all |
| Needs | nothing | one file, or the agent too |

The suspicious verdict is the interesting one. vspam.org scores indicators it
has not published to the blocklist — sparse-history domains, lookalikes under
review. A DNS return code has no way to say "we have an opinion but we are not
blocking on it". The module carries that through as a 1.5-weight nudge for the
rest of your rules to add up against.

## Install

Three files. From a checkout of this repository, or with `curl` from
`https://raw.githubusercontent.com/vspam-org/integrations/main/rspamd/`.

```bash
# 1. The module itself.
install -m 0644 vspam.lua /etc/rspamd/plugins.d/vspam.lua

# 2. Wire local.d/override.d for it. APPEND — do not overwrite; this file is
#    shared with anything else you have configured at the top level.
cat rspamd.conf.local >> /etc/rspamd/rspamd.conf.local

# 3. Options. Every key has the same default in the module, so this is
#    optional until you need to change one.
install -m 0644 local.d/vspam.conf /etc/rspamd/local.d/vspam.conf

rspamadm configtest && systemctl reload rspamd
```

Step 2 is only needed because Rspamd wires `local.d` automatically for the
modules it ships, not for third-party ones.

Weights come from the module itself, so there is nothing else to install. If
you want to tune them, `local.d/groups.conf` in this directory has the same
values written out — **merge** it into your existing file rather than replacing
it.

### With the agent

Optional, and worth it. `vspam-agent` answers from a local BoltDB cache instead
of a network round trip, covers the whole message in one request, and submits
what this server sees back to the pool — which is what makes the list useful to
the next operator.

```bash
# Debian/Ubuntu: see https://vspam.org/download
apt install vspam-agent
```

In `/etc/vspam/agent.yml`:

```yaml
http_enabled: true
http_listen: "127.0.0.1:10046"
api_key: "vspam_your_key_here"   # free, from https://vspam.org/account
```

The module's default `agent_url` already points there. When Rspamd and the
agent are in separate containers, set `agent_url` to the service name instead:

```
agent_url = "http://vspam-agent:10046";
```

### Without the agent

It still works. The module falls back to the public API and looks each
indicator up by SHA-256 — only the hash crosses the network, never the domain.
Slower than a local cache, and nothing is reported back, but it means you can
run the module before deciding to run a daemon.

Set `fallback_to_api = false` if you would rather a missing agent mean no
checking at all.

## Symbols

| Symbol | Weight | Meaning |
|---|---|---|
| `VSPAM_PHISHING` | 6.0 | Listed as phishing |
| `VSPAM_MALWARE` | 6.0 | Listed as malware distribution |
| `VSPAM_BOTNET` | 5.0 | Listed as botnet command and control |
| `VSPAM_SPAM` | 3.0 | Listed as a spam source |
| `VSPAM_THREAT` | 2.0 | Listed, category not one of the above |
| `VSPAM_TOR` | 0.5 | Tor exit node — context, not evidence |
| `VSPAM_SUSPICIOUS` | 1.5 | Scored suspicious, deliberately not listed |
| `VSPAM_FAIL` | 0.0 | Neither transport answered; nothing was checked |

These match the DNSBL return-code weights (`127.0.0.2` phishing, `.3` malware,
`.4` botnet, `.5` spam, `.6` tor, `.7` threat), so moving between the two paths
does not reweight your mail.

Rspamd rejects at 15 by default and greylists around 4, so a phishing hit
contributes strongly without rejecting on its own. That is deliberate: one list
should rarely be the only reason a message is refused.

**Start at zero.** Set every weight to `0.0` in `local.d/groups.conf` for the
first week. Symbols still appear in the history, so you can see exactly what
would have happened without touching delivery.

### One symbol per message

However many indicators are listed, the module inserts one. Which one differs
slightly by transport, and it is worth knowing which you are reading:

- **Agent:** answers with the first listing it finds, walking sender domain →
  connecting IP → URLs, and stops there. One request, no wasted lookups.
- **API fallback:** checks every indicator, then reports the strongest.

So a message whose sender is a known spam source *and* whose link is a known
phishing page scores `VSPAM_SPAM` through the agent and `VSPAM_PHISHING`
through the fallback. Same message, same weight class of decision, one symbol
either way.

## Which path

Run the module **or** the DNSBL, not both — the same finding would score twice.

Use the DNSBL if you want the shortest possible setup and only care about the
sender and the connecting IP: copy `../mailcow/rspamd/vspam.conf` to
`local.d/rbl.conf` and you are done. Use the module if you want URLs in the
body checked, the suspicious verdict, or the agent's cache and reporting.

If you do end up running both — say you already had the DNSBL and are trying
the module alongside it — `local.d/composites.conf` in this directory collapses
each duplicated pair back to a single weight. Both symbols stay visible in the
history so you can still see which path saw what.

## Failure behaviour

Every failure is open. A timeout, a refused connection, a 500 or an
unparseable body inserts `VSPAM_FAIL` at weight 0 and the message proceeds
unaffected. A blocklist that stops mail when it is unreachable is worse than no
blocklist.

`VSPAM_FAIL` at weight 0 is how you notice: it shows in the history and in
`rspamc counters` without ever affecting delivery. If you see it consistently,
the agent is down or the API is unreachable — nothing has been checked.

After a refused agent connection the module stops calling the agent for
`agent_cooldown` seconds (60 by default), so a stopped agent does not cost
every message a full connect timeout.

Messages from your own networks and from authenticated submitters are skipped
by default (`check_local`, `check_authed`) — the usual Rspamd convention, and
the right one for a public blocklist.

## Verify it works

```bash
rspamadm configtest
rspamc counters | grep VSPAM        # symbols registered?
```

With the agent running:

```bash
curl -s "http://127.0.0.1:10046/health"
# {"status":"ok"}
```

Then send yourself a message and look for `VSPAM_*` in the Rspamd history. For
debug detail on what was looked up, add to `local.d/logging.inc`:

```
debug_modules = ["vspam"];
```

## Tests

`test/run-tests.sh` runs the module against a real Rspamd in Docker, with a
mock standing in for the agent and the API. It needs nothing but Docker.

```bash
./test/run-tests.sh
```

It covers each category symbol, the unknown-category fold, the suspicious
verdict, URL and client-IP lookups, the agent → API fallback, and that a
message still passes when nothing is reachable. `KEEP=1` leaves the containers
up afterwards.

`test/mock-vspam-server.py` implements both wire contracts and is derived from
`agent/internal/httpcheck/server.go` and `agent/internal/checker/api_client.go`.
If either of those changes shape, the mock and the module both need to follow.

## False positives

Delist requests are reviewed by a human within 48 hours, need no account, and
are tracked publicly by ID: <https://vspam.org/delist>. Approval removes the
DNSBL publication and marks the report a false positive in our scoring history.

Check what we currently hold on a host before filing: <https://vspam.org/lookup>.

## Removing it

```bash
rm /etc/rspamd/plugins.d/vspam.lua /etc/rspamd/local.d/vspam.conf
# and drop the vspam { } block from /etc/rspamd/rspamd.conf.local
systemctl reload rspamd
```

Nothing else in your configuration is touched.
