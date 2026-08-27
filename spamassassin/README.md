# vspam.org for SpamAssassin

A rule package that checks three surfaces against `dnsbl.vspam.org` and scores
one rule per threat category:

| Surface | Plugin | What is asked |
|---|---|---|
| Connecting IP | DNSEval | the last external relay, reversed quads |
| Hostnames in the body | URIDNSBL | the **exact host**, not the registered domain |
| Sender domain | AskDNS | envelope sender *and* From header |

The existing three-line `check_rbl` snippet on
[vspam.org/integrations](https://vspam.org/integrations) checks only the
connecting IP and scores every listing the same. This does more, and says why.

## Install

Either copy the file, or subscribe to the update channel and stop thinking
about it. Do one or the other, not both — two copies means every rule is
defined twice.

### Copy the file

```bash
curl -fsSL https://raw.githubusercontent.com/vspam-org/vspam.org/main/integrations/spamassassin/20_vspam.cf \
  -o /etc/spamassassin/20_vspam.cf

spamassassin --lint && systemctl reload spamassassin
```

Amavis, `spamd`, `spamass-milter` and rspamd-free mailcow all read
`/etc/spamassassin/`, so nothing else changes.

### Subscribe to the channel

> **Not serving yet.** The channel is built, signed and tested end to end, but
> `updates.vspam.org` does not answer until the mirror and its DNS records go
> up. Copy the file for now; nothing about it changes when the channel lands,
> and `sa-update` will simply start keeping it current. Status is on
> <https://vspam.org/integrations>.

The channel is signed with **the same key as the apt and rpm repositories**,
so if you already install `vspam-agent` from packages, this is a key you
already trust. `sa-update` keeps its own keyring, so it still needs importing
there once.

```bash
curl -fsSL https://packages.vspam.org/rpm/RPM-GPG-KEY-vspam -o /tmp/vspam.key
sa-update --import /tmp/vspam.key

sa-update --channel updates.vspam.org --gpgkey <KEY_ID>
spamassassin --lint && systemctl reload spamassassin
```

The URL says rpm but the file is a plain ASCII-armored public key, and it is
the same key the apt repository publishes as
`https://packages.vspam.org/apt/vspam-archive-keyring.gpg`. Use either.

`<KEY_ID>` is the long key ID of that key, printed by the import, or:

```bash
gpg --show-keys --with-colons /tmp/vspam.key | awk -F: '/^fpr:/{print substr($10,25); exit}'
```

Then add the same `--channel` and `--gpgkey` to whatever already runs
`sa-update` on a timer. `sa-update` exits 1 when there was nothing new, which
is not an error — the usual cron idiom is `sa-update ... && systemctl reload
spamassassin`.

The key ID and the current channel status are published on
<https://vspam.org/integrations>. Updates are signed; `sa-update` refuses
anything it cannot verify against the key you imported, and runs its own
`--lint` on the rules before installing them.

## Rules

| Rule | Score | Meaning |
|---|---|---|
| `VSPAM_PHISHING` | 2.0 | Listed as phishing |
| `VSPAM_MALWARE` | 2.0 | Listed as malware distribution |
| `VSPAM_BOTNET` | 1.7 | Listed as botnet command and control |
| `VSPAM_SPAM` | 1.0 | Listed as a spam source |
| `VSPAM_THREAT` | 0.7 | Listed, category not one of the above |
| `VSPAM_TOR` | 0.2 | Tor exit node — context, not evidence |
| `VSPAM_SENDER_AND_URI` | 1.0 | Sender domain *and* a link in the body are listed |

The weights are the Rspamd module's weights divided by three, because
SpamAssassin's default spam threshold is 5.0 where Rspamd's reject threshold is
15.0. Same proportion of the budget, so the two integrations agree about what a
listing is worth.

A phishing hit is therefore 2.0 against a threshold of 5.0: strong, but not
enough on its own. That is deliberate — one list should rarely be the only
reason a message is refused.

**Start at zero.** Put `score VSPAM_PHISHING 0` and friends in your `local.cf`
for the first week. The rules still show up in `X-Spam-Status`, so you can see
exactly what would have happened before it affects delivery.

### One category, one score

Every DNS lookup is a private `__VSPAM_*` rule with no score of its own. Only
the metas at the bottom score. A message whose sender domain, connecting IP and
body link are all listed as phishing scores `VSPAM_PHISHING` once, not three
times.

`VSPAM_SENDER_AND_URI` is the exception, and is meant to stack: two independent
surfaces agreeing is worth more than either alone. Forging a sender domain is
routine; having the linked host listed as well means the message is what it
looks like.

### Exact hosts

The URI rules carry `tflags notrim`. Without it SpamAssassin trims a hostname
to its registered domain before querying, so a listing for
`bad-user.github.io` would be asked as `github.io` — which is not what is
listed, and would be a false positive against an entire platform if it ever
were. If you edit these rules, keep `notrim`.

## Tuning

Override in `/etc/spamassassin/local.cf`, never in `20_vspam.cf` — the channel
overwrites that file on every update.

```
score VSPAM_PHISHING 3.0
score VSPAM_TOR      0.0
```

To keep the rules but stop the lookups entirely, `score` every rule 0, or set
`skip_rbl_checks 1` (which also disables every other DNSBL you run).

## Verify it works

```bash
spamassassin --lint
grep -c '^meta *VSPAM' /etc/spamassassin/20_vspam.cf   # 7 scored rules

dig +short 2.113.0.203.dnsbl.vspam.org                 # your own listing check
```

Then run a message through and look at `X-Spam-Status` for `VSPAM_`.
`spamassassin -D askdns,uridnsbl -t < message.eml` shows every query made and
the answer.

If nothing ever fires, check that DNS actually works from the mail server —
SpamAssassin silently skips all network rules when it decides DNS is
unavailable. `spamassassin -D dns -t < message.eml 2>&1 | grep dns_available`
will say so.

## Publishing the channel

Maintainers only, and normally automated: `.github/workflows/spamassassin-channel.yml`
builds, signs and uploads on a `sa-channel-v*` tag or from the Actions tab. It
signs with the packaging key, lints the rules a client would install, and
uploads everything except the DNS records — those are printed in the job
summary, because they must go up only once the files are reachable.

**The channel name is a DNS name, not a host.** `sa-update` looks up TXT
records under `updates.vspam.org`; it downloads from whatever URL the
`MIRRORED.BY` file names. The workflow serves the files from
`packages.vspam.org/sa`, so there is one origin and one certificate to keep
working, and `updates.vspam.org` needs no hosting at all — only two kinds of
TXT record.

To run it by hand:

```bash
./publish-sa-update-channel.sh --gpg-key <KEY_ID> \
  --mirror https://packages.vspam.org/sa ./out
```

It writes the tarball, its checksums, a detached signature, `MIRRORED.BY`, the
exported public key, and `dns-records.txt`. Upload the files, then publish the
records — in that order. A client that reads a new serial and cannot fetch it
treats the channel as failed.

Each supported SpamAssassin release needs its own TXT record, because
`sa-update` asks for its own version reversed: 4.0.1 looks up
`1.0.4.updates.vspam.org`. The version list lives at the top of the script.

Serials are date-based (`YYYYMMDDHH`) and only have to increase; `sa-update`
compares them numerically against what the client already has.

## Tests

`test/run-tests.sh` runs the rules against a real SpamAssassin in Docker, with
CoreDNS standing in for `dnsbl.vspam.org`. It needs nothing but Docker.

```bash
./test/run-tests.sh              # lint + rule behaviour
./test/run-tests.sh --channel    # also publish a channel and sa-update from it
```

The channel phase is not a simulation: it signs a real tarball with a throwaway
key, serves it over HTTP, answers the DNS records `sa-update` looks for, runs
the real client end to end, and then corrupts the tarball to confirm the
signature check rejects it.

## False positives

Delist requests are reviewed by a human within 48 hours, need no account, and
are tracked publicly by ID: <https://vspam.org/delist>. Approval removes the
DNSBL publication and marks the report a false positive in our scoring history.

Check what we currently hold on a host before filing: <https://vspam.org/lookup>.

## Removing it

If you copied the file:

```bash
rm /etc/spamassassin/20_vspam.cf
spamassassin --lint && systemctl reload spamassassin
```

If you subscribed to the channel, drop `--channel updates.vspam.org` from
whatever runs `sa-update` first — otherwise the next run puts the rules back —
then:

```bash
rm -rf /var/lib/spamassassin/*/updates_vspam_org
spamassassin --lint && systemctl reload spamassassin
```
