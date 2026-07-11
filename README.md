# SSL Issue Checker

A Chrome extension that checks the TLS/SSL certificate, hosting, and domain-registration
details of whatever site is open in your active tab — in the toolbar popup, or in a
draggable floating panel that stays on the page across navigation.

## What it shows

**SSL** — protocol/cipher suite, certificate issue date and expiry (with a compact
"2y 3m ago" style duration), chain length and trust status, OCSP stapling, TLS handshake
time, and the certificate's covered hostnames.

**Hosting** — the `Server` header (and `X-Powered-By` if present), HTTP/2 support,
approximate server location (city/country with a flag), and network operator (ASN, linked
to Cloudflare Radar).

**Domain** — registrar, domain registration/expiry dates, detected DNS provider, and
registered owner organization.

Certificate issues (expired, self-signed, incomplete/untrusted chain, hostname mismatch,
outdated TLS version, no HTTPS at all) are called out explicitly with a severity level.

## How it works

```
extension/   Chrome extension (Manifest V3) — popup + persistent floating panel
backend/     Go Azure Function — does the actual TLS handshake, WHOIS, and geolocation lookups
release/     Web Store signing key + build zip (gitignored, not in this repo's history)
```

The extension never asks you to configure a backend URL or API key — it talks to a fixed,
already-deployed backend (`ssl-checker.anilrv.in`) and fetches its own access key from that
backend on first use. The backend performs a real TLS handshake against the site you're
viewing (with certificate verification intentionally disabled, since the goal is to
*inspect* invalid certs, not reject the connection because of one), then enriches the
result with a WHOIS lookup ([whoisjson.com](https://whoisjson.com)) and an IP geolocation
lookup ([ipgeolocation.io](https://ipgeolocation.io)) run concurrently with the probe.
Both enrichment lookups are best-effort — a slow or failed upstream never breaks the core
certificate check, it just leaves those fields blank.

Only the hostname of your active tab is ever sent anywhere; see
[`extension/privacy-policy.md`](extension/privacy-policy.md) for the full breakdown of what
each backend call sends and to whom.

## Development

### Backend

Requires Go and the [Azure Functions Core Tools](https://learn.microsoft.com/azure/azure-functions/functions-run-local).

```
cd backend
go build ./...
go vet ./...
go test ./...
```

To exercise the TLS probe, WHOIS, and geolocation lookups directly against real hosts
without deploying anything:

```
go run ./cmd/localtest
```

Running the function locally (`func start`) needs a `local.settings.json` with
`CHECKSSL_KEY`, `WHOISJSON_TOKEN`, and `IPGEOLOCATION_TOKEN` set — this file is gitignored
and never committed. Deploy with:

```
func azure functionapp publish ssl-checker
```

### Extension

No build step. In `chrome://extensions`, enable **Developer mode**, click
**Load unpacked**, and select the `extension/` folder. After any change, reload the
extension from that page to pick it up.

## License

No license has been chosen yet — all rights reserved by default until one is added.
