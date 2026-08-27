# vspam.org integrations

[![protected by vspam.org](https://api.vspam.org/api/v1/badge/protected.svg)](https://vspam.org/)
[![Tests](https://github.com/vspam-org/integrations/actions/workflows/test.yml/badge.svg)](https://github.com/vspam-org/integrations/actions/workflows/test.yml)

Tested filter configuration for [vspam.org](https://vspam.org), a collaborative
phishing and abuse blocklist for mail operators. Querying the list is free, and
a delist request needs no account.

Every directory here has a test suite that runs against the real filter in
Docker — not a mock. If you change something, run it.

## Start here: you may not need any of this

The DNSBL path needs nothing installed and works with whatever already does RBL
lookups:

```conf
# Postfix, /etc/postfix/main.cf
smtpd_recipient_restrictions =
    permit_mynetworks,
    permit_sasl_authenticated,
    reject_unauth_destination,
    reject_rbl_client dnsbl.vspam.org
```

```bash
dig +short 19.72.234.185.dnsbl.vspam.org
# 127.0.0.2 means listed as phishing; no answer means not listed
```

Zones answer `127.0.0.2` phishing, `.3` malware, `.4` botnet C2, `.5` spam,
`.6` Tor exit, `.7` aggregated. Matching anywhere in `127.0.0.0/8` treats every
listing alike, which is the safe default.

## What each integration adds

| | What it gives you that the DNSBL cannot | Install |
|---|---|---|
| **[rspamd/](rspamd/)** | **Every URL in the message body**, a symbol per category, and the suspicious-but-not-listed verdict a DNS return code cannot express | 1 file, or the agent too |
| **[spamassassin/](spamassassin/)** | Three lookup surfaces and seven scored metas, kept current by a signed `sa-update` channel | `sa-update --channel` |
| **[ansible/](ansible/)** | The agent across a fleet, with a Postfix failure mode that lets mail through | one playbook |
| **[mailcow/](mailcow/)** | Compose override plus an rspamd drop-in | 2 files |

## One thing not to skip

Postfix defaults to `smtpd_policy_service_default_action = "451 4.3.5 Server
configuration problem"` on a 100-second timeout. If you use the agent's policy
service, set the failure mode **before** you add the dependency on it:

```conf
smtpd_policy_service_default_action = DUNNO
smtpd_policy_service_timeout = 10s
```

Otherwise the day the agent is restarting, upgrading or wedged, Postfix defers
every inbound message, 100 seconds at a time, until someone notices. A
blocklist that stops mail when it cannot be reached is worse than no blocklist.
The Ansible role does this for you.

## Tests

Docker, plus `ansible-playbook` for the Ansible suite. Nothing else.

```bash
./rspamd/test/run-tests.sh                  # real rspamd, agent and API mocked
./spamassassin/test/run-tests.sh --channel  # real spamassassin, real sa-update
./ansible/test/run-tests.sh                 # real Debian under systemd, real Postfix
```

They run against the real filters because untested rules do not belong in
anyone's mail path. `KEEP=1` on any of them leaves the containers up.

## If we get one wrong

<https://vspam.org/delist> — no account, no fee, reviewed by a human within 48
hours. False positives are the failure mode that matters and they are only
visible to the person affected, so telling us is the contribution.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Licence

Code **AGPL-3.0** ([LICENSE](LICENSE)). The blocklist data is free to use and
redistribute for **non-commercial** purposes with attribution — "Data provided
by vspam.org" — and commercial use needs a licence
([LICENSE-DATA](LICENSE-DATA)). Those are deliberately different licences.
