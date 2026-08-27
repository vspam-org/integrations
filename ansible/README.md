# vspam.org for Ansible

An Ansible role that installs the vspam.org agent across a mail server fleet
from the signed package repositories, writes its config, starts it, and — only
if you ask — points Postfix at it.

```bash
cp inventory.example.ini inventory.ini   # edit
ansible-playbook -i inventory.ini playbook.yml
```

That is the whole thing on a fleet of any size. The role is idempotent, so it
is safe to leave in a nightly run.

## What it does

1. Adds the signed apt or yum repository — the same one and the same key as
   the manual instructions on [/download](https://vspam.org/download), so
   `apt upgrade` keeps the fleet current afterwards.
2. Installs `vspam-agent`.
3. Templates `/etc/vspam/agent.yml` from role variables, `0640 root:vspam`,
   keeping a backup of the previous file.
4. Enables and starts the service.
5. **Waits until the agent actually answers** before reporting success.
6. Optionally wires Postfix.

Step 5 is what makes step 6 safe to run in the same play: Postfix is never
pointed at a policy service that has not already responded.

## The Postfix step is off by default, and why

`vspam_agent_configure_postfix: true` does three things:

```
smtpd_policy_service_default_action = DUNNO
smtpd_policy_service_timeout = 10s
smtpd_recipient_restrictions = <your existing list>, check_policy_service inet:127.0.0.1:10045
```

The first two matter more than the third.

Postfix ships `smtpd_policy_service_default_action = 451 4.3.5 Server
configuration problem` with a 100-second timeout. Add a policy service and
leave those alone, and the day the agent is restarting, upgrading or wedged,
**Postfix defers every inbound message** — 100 seconds at a time. A blocklist
that stops mail when it cannot be reached is worse than no blocklist, so the
role sets the failure mode before it adds the dependency on it.

The restriction list is appended to, never replaced: the order in it is your
spam policy and it is load-bearing. If your list is empty, the role writes
`permit_mynetworks` ahead of the policy service so that turning this on does
not start policy-checking your own users' submissions.

It is off by default because editing `main.cf` on a running MTA is not
something a role should do merely because it was installed. Read the above,
then turn it on.

## Variables

Full list with comments in [`roles/vspam_agent/defaults/main.yml`](roles/vspam_agent/defaults/main.yml).
The ones you are likely to set:

| Variable | Default | |
|---|---|---|
| `vspam_agent_api_key` | `""` | Optional. Raises submission limits and attributes reports to your profile. Vault it. |
| `vspam_agent_listen` | `tcp://127.0.0.1:10045` | `unix:///var/run/vspam/agent.sock` for a single-host Postfix |
| `vspam_agent_configure_postfix` | `false` | See above |
| `vspam_agent_version` | `latest` | Pin a version on a fleet you roll forward deliberately |
| `vspam_agent_http_enabled` | `true` | The check API — Exim, OpenSMTPD, Rspamd, scripts, monitoring |
| `vspam_agent_dnsbl_enabled` | `true` | Answer from DNS as well as the API |
| `vspam_agent_extra_config` | `{}` | Passed through to `agent.yml` verbatim, for a key newer than this role |

### The API key

The agent works without one. A key raises your submission limits and
attributes what your servers report to your reporter profile.

Keep it in a vault rather than in the playbook:

```bash
ansible-vault encrypt_string --name vspam_agent_api_key 'vsk_...'
```

The task that writes it is `no_log`, so it stays out of Ansible's output and
logs either way.

## Tags

```bash
ansible-playbook -i inventory.ini playbook.yml --tags vspam_agent_config   # config only
ansible-playbook -i inventory.ini playbook.yml --tags vspam_agent_verify   # just check the fleet
```

## Platforms

Debian and Ubuntu via apt, RHEL/Rocky/Alma via dnf. Anything else: install the
static binary from [/download](https://vspam.org/download) — the role asserts
rather than guessing.

## Tests

```bash
./test/run-tests.sh
```

Needs Docker and `ansible-playbook`, nothing else. It boots a real Debian 12
container under systemd, installs the real package from the real signed
repository, and asserts across four scenarios: fresh install, idempotence,
Postfix wiring (including that Postfix ends up failing *open*, and that
`postfix check` still accepts what we wrote), and a config change restarting
the agent with the health endpoint still answering afterwards.

`KEEP=1 ./test/run-tests.sh` leaves the container up.

## Scope

This role installs the **agent** on your mail servers. It is not the playbook
that runs vspam.org itself — that one provisions nginx, certbot and Postgres
backups against our own hosts, and lives in the development repository where
it belongs. Nothing here assumes anything about your infrastructure beyond a
reachable host and a way to become root.
