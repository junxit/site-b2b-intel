# Sample scans — first research pass

> **These results are a snapshot from 2026-05-26 and are not maintained.**
> They were produced by the 0.1.0 catalog (20 vendors, 41 rules), before
> CAA, CNAME and DMARC-vendor detection existed — a scan run today returns
> considerably more. DNS changes constantly, so treat every line below as
> "what these domains published on that date", not as current fact.
>
> Reproduce rather than cite: `b2b-intel scan <domain>`.

**Method.** Every value is derived from public DNS records — TXT, MX, NS,
SPF and DKIM — read from a public recursive resolver. No HTTP requests, no
page scraping, no JavaScript execution, no authenticated access. Each
"signals" entry is the fingerprint rule pattern that matched.

## Counts across this 6-domain sample

Six hand-picked domains is a sample, not a market. These counts describe
only the table below and say nothing about vendor market share — do not
cite them as adoption statistics.

| Vendor | Category | Domains where detected |
|---|---|---|
| Google Workspace | productivity | 6 / 6 |
| Atlassian | dev-collab | 5 / 6 |
| Microsoft 365 | productivity | 5 / 6 |
| Meta (Facebook) | social | 4 / 6 |
| SendGrid (Twilio) | email-api | 4 / 6 |
| Stripe | payments | 4 / 6 |
| Apple | identity | 3 / 6 |
| Cloudflare | cdn | 3 / 6 |
| DocuSign | esign | 3 / 6 |
| Mailchimp (Intuit) | marketing | 3 / 6 |
| AWS Route 53 | dns | 2 / 6 |
| AWS Simple Email Service | email-api | 2 / 6 |
| Adobe | marketing | 2 / 6 |
| Zendesk | support | 2 / 6 |
| Salesforce | crm | 1 / 6 |
| Shopify | commerce | 1 / 6 |

## Per-domain breakdown

### stripe.com
* **Google Workspace** — DKIM `google` selector, MX `aspmx.l.google.com` + `.googlemail.com`, TXT `google-site-verification=`
* **Microsoft 365** — TXT `MS=`
* **AWS Route 53** — NS `*.awsdns-*.{com,net,org,co.uk}`
* **AWS Simple Email Service** — `_amazonses.stripe.com` exists
* **SendGrid** — DKIM `s1`, `s2` selectors
* **Mailchimp (Intuit)** — DKIM `mandrill` selector
* **DocuSign** — TXT `docusign=`
* **Atlassian** — TXT `atlassian-domain-verification=`
* **Apple** — TXT `apple-domain-verification=`
* **Meta (Facebook)** — TXT `facebook-domain-verification=`
* **Stripe** — TXT `stripe-verification=` (self)

### github.com
* **Microsoft 365** — DKIM `selector1`, MX `*.mail.protection.outlook.com`, SPF `spf.protection.outlook.com`, TXT `MS=`
* **AWS Route 53** — NS pattern
* **Google Workspace** — DKIM `google`, TXT verification
* **SendGrid** — DKIM `s1`, `s2`, `smtpapi`, SPF `sendgrid.net`
* **Mailchimp (Intuit)** — DKIM `k1`, `k2`, SPF `mcsv.net`
* **Salesforce** — SPF `_spf.salesforce.com`
* **Zendesk** — SPF `mail.zendesk.com`
* **Atlassian** — TXT verify
* **DocuSign** — TXT verify
* **Adobe** — TXT `adobe-idp-site-verification=`
* **Apple** — TXT verify
* **Meta (Facebook)** — TXT verify
* **Shopify** — TXT `shopify-verification-code=`
* **Stripe** — TXT `stripe-verification=`

### shopify.com
* **Google Workspace** — DKIM, MX, SPF, TXT
* **Microsoft 365** — TXT `MS=`
* **AWS Simple Email Service** — `_amazonses.shopify.com` present
* **SendGrid** — DKIM `smtpapi`, SPF `sendgrid.net`
* **Zendesk** — SPF `mail.zendesk.com`
* **DocuSign**, **Atlassian**, **Adobe**, **Apple**, **Meta**, **Stripe** — TXT verifications

### anthropic.com
* **Google Workspace** — DKIM `google`, MX `aspmx.l.google.com`, SPF `_spf.google.com`, TXT verification
* **Microsoft 365** — TXT `MS=`
* **Cloudflare** — NS `*.ns.cloudflare.com`
* **Atlassian**, **Stripe** — TXT verifications

### basecamp.com
* **Google Workspace** — DKIM `google`, TXT verification
* **Microsoft 365** — TXT `MS=`
* **Cloudflare** — NS
* **Mailchimp (Intuit)** — DKIM `k1`, SPF `mcsv.net`
* **SendGrid** — DKIM `smtpapi`
* **Atlassian** — TXT verify

### notion.so
* **Cloudflare** — NS
* **Google Workspace** — TXT verification
* **Meta (Facebook)** — TXT verify

## Observations

1. **Google Workspace is universal** across this sample — 6/6 of the domains have it. Both MX-based and TXT-verification signals agree.
2. **TXT verification tokens are noisy** — they linger after a vendor is removed (a domain can hold a stale `docusign=` token long after DocuSign is uninstalled). Treating them as "ever used" rather than "currently using" is more honest.
3. **DKIM selectors are strong vendor signals.** Selector names like `mandrill`, `smtpapi`, `k1` are essentially proprietary to a single sender.
4. **`_amazonses.<domain>` is an excellent AWS SES probe** — it's only present if the domain has been verified in SES.
5. **DMARC `rua=` is unmined** — the parser builds `DMARC_RUA` records but no vendor rules consume them yet. Adding a few DMARC vendors (dmarcian, Valimail, Postmark, EasyDMARC) is a cheap next win.
6. **CNAME signals are completely missing.** They'd require probing common SaaS subdomains (`shop.*`, `support.*`, `*.hubspot.*`, etc.) which the current resolver doesn't do.

## How this was produced

```bash
B2B_INTEL_DB_PATH=/tmp/b2b-e2e.db uv run b2b-intel init
for d in stripe.com github.com shopify.com anthropic.com basecamp.com notion.so; do
  B2B_INTEL_DB_PATH=/tmp/b2b-e2e.db uv run b2b-intel scan "$d"
done
B2B_INTEL_DB_PATH=/tmp/b2b-e2e.db uv run b2b-intel report stripe.com
```
