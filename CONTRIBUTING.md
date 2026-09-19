# Contributing

Short version: **this repository is source-available, not open source, and
is not currently accepting external contributions.**

## Why not

The code is published under a proprietary, all-rights-reserved license (see
[LICENSE](LICENSE)). Accepting patches into a proprietary codebase without a
contributor license agreement creates a genuine ownership problem — the
contributor retains copyright in their patch, which makes the combined work
un-relicensable later. Rather than leave that ambiguity sitting in the
history, pull requests are closed unmerged.

If that changes, this file changes with it.

## What is useful

**Bug reports and corrections are welcome** via
[issues](https://github.com/junxit/site-b2b-intel/issues), and are
particularly valuable for the fingerprint catalog:

- A rule that fires on a domain not actually using the vendor (false positive)
- A vendor whose DNS pattern changed, so the rule no longer matches
- A vendor with a detectable DNS signature that isn't in the catalog yet

For any of these, please include **the live DNS evidence** — the domain, the
record type, and the record value:

```console
$ dig +short CAA example.com
0 issue "letsencrypt.org"
```

That matters more than it might seem. Every pattern in this catalog was
verified against a real record before it landed, and doing so caught five
that would otherwise have been wrong — Statuspage publishes as
`stspg-customer.com`, not `statuspage.io`; Valimail as `vali.email`;
EasyDMARC as `rua.easydmarc.us`; Google Trust Services as `pki.goog`;
Comodo as `comodoca.com`. A fingerprint written from memory doesn't fail
loudly. It just silently never matches, and the vendor quietly becomes
undetectable.

## Running the checks locally

```bash
uv sync
uv run pytest              # full suite, runs entirely offline
uv run b2b-intel rules validate
```

`rules validate` catches undetectable vendors, duplicate rules, and suffix
patterns without a leading dot (`suffix: zendesk.com` would also match an
attacker-registered `fakezendesk.com`). Both run in CI.

## Security

If you find a security issue, please report it privately through GitHub
security advisories rather than opening a public issue.
