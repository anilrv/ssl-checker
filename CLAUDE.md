# SSL Issue Checker

A Chrome extension (Manifest V3) paired with a Go Azure Functions backend. The extension
shows the TLS certificate, hosting, and domain-registration details for whatever site is
open in the active tab, either in the toolbar popup or in a persistent floating panel drawn
on the page itself.

Live backend: `https://ssl-checker.anilrv.in`

## Repository layout

```
backend/     Go Azure Function (module: sslcheckerfunc)
extension/   Chrome extension (Manifest V3)
release/     Chrome Web Store signing key + upload zip — gitignored, never commit
```

`release/*.pem` is the extension's manifest signing key and `release/*.zip` is a build
artifact; both are gitignored on purpose. `backend/local.settings.json` and
`backend/bin/` are also gitignored (local secrets and a compiled binary, respectively).

## Backend (`backend/`)

Real TLS handshakes via `crypto/tls`/`crypto/x509` (`InsecureSkipVerify: true` is
deliberate — the whole point is to inspect invalid/expired/self-signed certs, not reject
the connection because of them). Package layout:

- `main.go` — HTTP handlers, route registration, the `CheckResult` response shape, and the
  in-memory per-instance rate limiter.
- `certprobe/` — the TLS probe itself: handshake, chain verification, ALPN, OCSP stapling,
  SCT count, handshake timing, and the `Server`/`X-Powered-By` headers (fetched by reusing
  the already-open connection — see the HTTP/2 gotcha below).
- `geoip/` — IP → country/city/ASN via ipgeolocation.io.
- `whois/` — hostname → registrar/registration dates/DNS provider/owner org via
  whoisjson.com (uses `golang.org/x/net/publicsuffix` to reduce a subdomain to its
  registrable domain, since WHOIS operates at the domain level).
- `ssrfguard/` — resolves a hostname to a public IP only; rejects private/loopback/link-local
  targets before the probe ever dials out.
- `cmd/localtest/` — a standalone harness (`go run ./cmd/localtest`) that exercises the
  probe/geoip/whois packages directly against real hosts, without needing a deployed
  function or a function key.
- `static.go`/`static/`, `privacy.go`/`privacy.html`, `home.html` — the favicons and the
  two plain HTML pages served at `/` and `/api/privacy`.

### Routes

| Route | Auth | Purpose |
|---|---|---|
| `GET /api/checkssl?host=` | function key | Runs the probe, returns `CheckResult` JSON. |
| `GET /api/bootstrap` | anonymous | Returns the function key so the extension never has to ask the user for one. Gated **only** by per-IP rate limiting — see below. |
| `GET /api/privacy` | anonymous | Privacy policy page. |
| `GET /` | anonymous | Landing page. |
| favicons / manifest icons | anonymous | Static assets. |

**Bootstrap has no Origin check, and that's intentional, not a gap.** Chrome never sends a
real `Origin` header on a fetch from an extension page unless the extension has
`host_permissions` for the target host — confirmed against Chromium's own docs after a
production 403 traced back to exactly this. This extension deliberately has no
`host_permissions` (to avoid the install-time "read and change data on all websites"
warning for the popup/background contexts), so an Origin check here can never see real
traffic. Don't reintroduce one; the function key isn't meant to be secret from real users
of the extension anyway — the goal is deterring casual scraping, and rate-limiting alone
already does that.

### Conventions that matter here

- **Every third-party API key lives in Azure Function app settings, never hardcoded and
  never committed.** Currently: `CHECKSSL_KEY`, `WHOISJSON_TOKEN`, `IPGEOLOCATION_TOKEN`
  (plus Azure-managed settings). Local equivalents go in `local.settings.json`, which is
  gitignored.
- **Best-effort external lookups (`geoip`, `whois`) must never surface as request errors.**
  Each owns a short, fixed timeout (2s) independent of the parent context's remaining
  deadline, and returns `nil` on any failure — a slow or dead upstream degrades the
  response, it never fails it. Follow this pattern for any new lookup in the same vein.
- **Three different lookups, three different auth schemes** — don't reach for the wrong
  one by habit: WHOIS uses `Authorization: TOKEN=<token>`; geolocation uses a `?apiKey=`
  query parameter; the function-key auth for `checkssl` is Azure's own platform mechanism.
- **Bounded LRU caches**, one per lookup, keyed at the right granularity: `main.go`'s
  `resultsCache` (hostname, 500 entries, 24h), `geoip`'s (IP, 500, 7 days — IP-to-ASN/geo
  data changes slowly), `whois`'s (registrable domain, 500, 30 days — persistence via the
  durable Table Storage tier is what makes a long TTL pay off against whoisjson.com's
  1000-request/month budget). Only successful lookups are cached, so a transient failure
  self-heals on the next request instead of being cached as a permanent miss.
- **Per-entry TTLs are capped at the data's own expiry** (`cappedTTL` in `main.go` and
  `whois.go`): a result whose cert `NotAfter` or domain expiration falls inside the
  default TTL window expires from the cache at that moment instead, so a cached "valid"
  is never served past the point it stops being true. Already-expired data gets a 5-minute
  floor (`minCacheTTL`) — cached briefly, so a renewal shows up within minutes. Durable
  reads additionally guard against pre-cap legacy rows by treating expired-data hits as
  misses.
- **HTTP/2 requires a different code path for reading response headers.** A connection
  that negotiated ALPN `h2` only understands HTTP/2 framing from that point on — writing a
  raw HTTP/1.1 request line over it doesn't error, it just silently never produces a
  parseable response. `certprobe.fetchServerHeaders` branches on
  `tlsConn.ConnectionState().NegotiatedProtocol == "h2"` and uses
  `golang.org/x/net/http2.Transport.NewClientConn` in that case. This was a real shipped
  bug (Server header silently empty for every h2 site, i.e. most of the modern web) before
  the branch existed — if you touch this function, keep both paths and test against an h2
  site (e.g. `www.google.com`) and a `http/1.1` one (e.g. `self-signed.badssl.com`).
- **The backend owns issue metadata.** `issueCatalog` in `main.go` maps every issue code
  to its label and severity, and `setIssues` ships them per-result as `issueDetails`
  alongside the bare `issues` codes. The extension renders from `issueDetails` and treats
  its own JS maps as fallback only (for its client-side `no-https` code and rows cached
  before the field existed) — so **a new rule is a backend-only deploy**: add the catalog
  entry and the rule in `computeIssues`, never touch the extension maps. If a rule is
  time-based, also add its threshold-crossing instant to `resultTTL` as a **future-only**
  deadline (`futureDeadline`) — passing an already-crossed threshold into `cappedTTL`
  would floor virtually every mature result to the 5-minute minimum.
- **Revocation checking is three-step and paranoid about its URLs**
  (`certprobe/revocation.go`): stapled OCSP → live OCSP → CRL, best-effort like
  geoip/whois, and only a definitive verdict is reported ("couldn't determine" stays
  silent — an unreachable responder is not evidence). Two things are easy to get wrong
  here: (1) OCSP/CRL URLs come out of the probed certificate, i.e. they're
  attacker-influenced, so every fetch resolves through `ssrfguard`, dials the vetted IP
  directly, and refuses redirects; (2) **Let's Encrypt shut down OCSP in August 2025**,
  so for the web's largest CA the CRL path is the only one that works — don't "simplify"
  it away. Test against `revoked.badssl.com` (an LE cert, exercises exactly that path).

### Build, test, deploy

```
cd backend
go build ./...
go vet ./...
go test ./...
go run ./cmd/localtest        # exercise probe/geoip/whois against real hosts, no deploy needed
func azure functionapp publish ssl-checker
```

## Extension (`extension/`)

Manifest V3. Two independent surfaces read the same `CheckResult`:

- **Popup** (`popup.html`/`popup.js`/`popup.css`) — the toolbar action. Always resets to
  the active tab's current result on open.
- **Floating panel** (`content.js`) — injected via a real `content_scripts` entry
  (`matches: ["https://*/*"]`, not `activeTab`/`scripting`) so it survives page navigation
  instead of dying with a one-shot injected script. This was a deliberate tradeoff: it
  costs the "read and change data on all websites" install warning, accepted explicitly so
  the floating view stays useful across normal browsing. Rendered inside a Shadow DOM
  (`attachShadow({mode:'open'})`) for style isolation from the host page. Has a compact
  (2-line org/issuer) and full mode, toggled via `chrome.storage.local`.
- `background.js` — runs the check per tab, caches the latest result per `tabId`, answers
  `getResult` messages from `content.js` and pushes `sslResult` messages on update.
- `lib/config.js` — fixed backend URL, no user-facing setup. Fetches the function key once
  from `/api/bootstrap` and caches it in `chrome.storage.local`. The retry-on-401/403
  (re-bootstrap once, covers key rotation) lives in the callers — `background.js` and
  `popup.js` — not in this module.

### Conventions that matter here

- **`extensionAlive()` guard before every `chrome.*` call in `content.js`.** A content
  script left attached to an already-open tab from before a dev reload has its `chrome.*`
  access revoked; without the guard this throws "Extension context invalidated" instead of
  quietly no-oping.
- **`currentHostname` is a `const`, and every async response is checked against it** before
  being applied. Background's cached result (or a slow in-flight check) can resolve *after*
  the user has already navigated to a different page — accepting it unconditionally shows
  the wrong site's data for a moment. Same pattern applies to any new message type added to
  the content script.
- **Drag handling excludes interactive children.** `attachDrag`'s `pointerdown` handler
  bails via `e.target.closest('button, input')` before starting a drag — without it,
  `setPointerCapture` on the drag handle swallows clicks on buttons/inputs nested inside it.
- Dates render via a calendar-aware year/month/day breakdown (`durationParts` in both
  `popup.js` and `content.js`), not a raw day-count divided by 30/365 — the latter drifts
  and can produce nonsense like "12m" instead of rolling over to a year.

### Local development

Load unpacked: `chrome://extensions` → enable Developer mode → **Load unpacked** →
select `extension/`. Chrome pins the extension to the exact folder path it was loaded
from — if the repo is ever moved, remove and re-add the unpacked extension.

### Publishing to the Chrome Web Store

The store item ID is `ondenicnbkaepibppfhcafdlfidgfpbm` — it MUST stay this value,
because the Azure Function app whitelists it. The ID is pinned three ways: the `"key"`
field in `manifest.json` (for unpacked installs), the private key
`release/ssl_plugin_extension_key.pem` (never commit, never lose — the ID is
unrecoverable without it and reserved forever by the store), and the published item
itself (never delete the item; the store blocks re-uploading a deleted item's key).

Upload-zip rules (learned the hard way; the store's docs don't spell these out):

- Zip the CONTENTS of `extension/` (manifest at zip root), excluding
  `privacy-policy.md`/`STORE_LISTING.md`.
- **Strip the `"key"` field from the zipped manifest** — first-time uploads are rejected
  if it's present (update uploads tolerate it). Keep it in the repo's manifest for
  unpacked dev installs.
- The first upload included the signing key as `key.pem` at the zip root to force the
  store to assign the pinned ID. **Update uploads don't need `key.pem`** — the store
  already knows the ID and re-signs packages itself.
- Bump `"version"` in `manifest.json` for every update upload, and update the privacy
  tab if data flows change (the hostname-to-backend call is declared as "Web history"
  collection).

## Required Azure Function app settings

`CHECKSSL_KEY`, `WHOISJSON_TOKEN`, `IPGEOLOCATION_TOKEN` (plus whatever Azure itself
manages, e.g. `AzureWebJobsStorage`). None of these are ever committed; they live only in
Azure app settings and, for local runs, `backend/local.settings.json` (gitignored).
