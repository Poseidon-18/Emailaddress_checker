# Mailbox Check

Paste a list of email addresses and get a verdict for each one:

| Result | Meaning |
|---|---|
| **Likely delivered** | The domain accepts mail and its server accepted the recipient. |
| **Likely to bounce** | Bad syntax, a domain that does not exist or refuses mail, or a server that says the mailbox does not exist. |
| **Unknown** | Nothing reliable can be said: the server refuses to answer, is greylisting, accepts every address, or the check could not run. |


## How it works

Each address goes through a pipeline and stops at the first conclusive result.

1. **Syntax** – RFC 5321 length limits, allowed characters, valid domain labels (IDNs are converted to punycode).
2. **DNS** – MX lookup. No domain → bounce. A *null MX* (RFC 7505) → bounce. No MX but an A/AAAA record → treated as the implicit MX (RFC 5321). DNS timeouts → unknown.
3. **SMTP probe** – connect to the best MX on port 25, run `EHLO`, `MAIL FROM`, `RCPT TO:<address>`, then `QUIT`.
   **The probe never sends `DATA`, so no message is ever delivered to anyone.** Reply codes are interpreted:
   `250` accepted; `550/551/553` with "user unknown"-style text or enhanced code `5.1.x` means no such mailbox; `4xx` (greylisting) and policy or blocklist refusals are *unknown*, not bounce.
4. **Catch-all detection** – after a recipient is accepted, a second `RCPT TO` with a random address at the same domain is tried. If that is accepted too, the server accepts everything, so the result is *unknown* rather than a false "delivered". Cached per domain.

Extras: duplicate removal, disposable-domain and role-account flags, a 50-address cap per run, parallel checks, CSV export, and refusal to probe MX hosts that resolve to private or internal IPs.

## What the deployed version can and cannot check

Many hosts block outbound port 25 to fight spam. On free Render instances, outbound SMTP is blocked (as of my last check; verify against Render's current docs). The app tests this at startup and shows a banner in the UI:

- **Port 25 blocked (the free deployment):** syntax and DNS checks run fully, so invalid addresses and dead domains are correctly reported as *likely to bounce*. Addresses at working domains come back **Unknown** with the reason "mailbox could not be checked".
- **Port 25 open (run it locally, or on a VPS that allows SMTP):** the full pipeline runs and mailbox-level verdicts are produced.

Even with port 25 open, big providers (Microsoft 365, Yahoo, many corporate gateways) accept or refuse RCPT for policy reasons and will correctly show as Unknown. No tool can fully fix that.

## Run locally

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python app.py            # http://127.0.0.1:5000
pytest                   # unit tests (DNS/SMTP are mocked)
```

Many home ISPs block port 25 too. The banner tells you.

Optional environment variables: `SMTP_PROBE` (`auto`|`on`|`off`), `PROBE_HELO`, `PROBE_MAIL_FROM` (set these to a domain you own for best results), `SMTP_TIMEOUT`, `MAX_ADDRESSES`.

## Deploy (Render)

New Web Service → connect this repo → Render reads `render.yaml`. Start command: `gunicorn app:app --workers 1 --threads 8 --timeout 120`.

## API

`POST /api/check` with `{"emails": "a@x.com, b@y.com"}` returns results, summary and counts. `GET /api/status` reports whether SMTP probing is available.

## Limitations

Verdicts are probabilistic. A mailbox can be accepted at RCPT and still bounce later, and vice versa. Probing from a fresh IP can get it rate-limited, so use this on your own lists and sparingly.
