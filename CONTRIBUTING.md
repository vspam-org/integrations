# Contributing

These configs sit in front of real mail. That shapes everything below: a wrong
rule bounces someone's invoice, and a change that fails open is better than one
that fails closed.

## Where the source lives

This repository is a **mirror**. These files are developed in the vspam.org
development repository alongside the API, the agent and the site, because the
SpamAssassin channel is signed and published from there with keys that should
not live in a public repository.

Practically:

- **Open an issue here.** That is the best way to reach us about anything in
  this repository, and it is where the discussion should happen.
- **A pull request is welcome too.** It is applied upstream rather than merged
  here, and closed with a link to the commit that carried it. You keep
  authorship on that commit.
- `main` here is force-updated from upstream, so do not build long-lived
  branches on it. Branch from a tag or a known commit if you need stability.

## The most valuable contributions

Not code, mostly.

1. **Tell us your integration is wrong.** These are tested against real rspamd,
   SpamAssassin and Postfix, but not against *your* deployment. A report that
   starts "this snippet does not work on…" is worth more than a feature.
2. **File a delist request when we get one wrong** — <https://vspam.org/delist>,
   no account needed. False positives are only visible to the person affected.
3. **Report indicators** — the browser extension, `vspam-agent report`, or
   <https://vspam.org/submit>.
4. Then code.

## Running the tests

Docker, plus `ansible-playbook` for the Ansible suite. Nothing else.

```bash
./rspamd/test/run-tests.sh
./spamassassin/test/run-tests.sh --channel
./ansible/test/run-tests.sh
```

If you change anything here, run the suite for it. Untested filter rules do not
belong in anyone's mail path. `KEEP=1` leaves the containers up so you can poke
at what failed.

## What we look for in a change

- **Fail open.** Every lookup path lets the message through when it cannot get
  an answer, and records that it could not. That applies to the configuration
  we hand people too: Postfix defers every message when a policy service is
  unreachable, so any snippet with `check_policy_service` in it also needs
  `smtpd_policy_service_default_action = DUNNO`. We shipped nine that did not.
- **Tests that pass for the right reason.** A fixture that happens to be shaped
  favourably is not coverage. We had one pass because its two-hop mail layout
  put the trustworthy header exactly where the buggy code was reading.
- **Trust boundaries in mail are not obvious.** `Received` headers are
  prepended, so only the topmost one was written by your own MX; everything
  below it is what the sender chose to send. We shipped that backwards once.
- **Do not invent numbers.** If a metric is not derivable from what is stored,
  it does not get displayed.

## Commits

Conventional subject, then prose explaining **why** — what was wrong, what the
tradeoff was, what you decided against. Reviewers can read the diff; they
cannot read your reasoning.

```
fix(rspamd): stop logging an error for every non-IP indicator
```

No AI-assistance references in commit messages. Never commit secrets, keys or
personal data.

## Licence

Code is **AGPL-3.0**; the blocklist data is under the separate terms in
`LICENSE-DATA` — free for non-commercial use with attribution, commercial use
by licence. By contributing you agree your contribution is licensed under the
same terms.
