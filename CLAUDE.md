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
- `whois/` — hostname → registrar/registration dates/DNS provider/owner org by querying
  the domain's own registry directly: RDAP first, falling back to port-43 WHOIS text
  parsing for TLDs with no RDAP server (e.g. `.be`). No third-party API, no token. The
  protocol clients (`whois/internal/{domain,model,rdap,srcerr,whoisclient}`) are vendored
  from [who-dat](https://github.com/lissy93/who-dat) (MIT licensed, see
  `whois/internal/LICENSE-who-dat`) — see the vendoring note below before touching them.
- `ssrfguard/` — resolves a hostname to a public IP only; rejects private/loopback/link-local
  targets before the probe ever dials out. `NeverPubliclyResolvable` rejects IP literals
  and reserved/private-use TLDs (`.local`, `.internal`, `.home.arpa`, etc. — verified
  against the IANA Special-Use Domain Names registry) before any DNS query is even made;
  `whois.Lookup` calls this same check before its own network request, so `whois` depends
  on `ssrfguard` for that classification, not the other way around.
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
  never committed.** Currently: `CHECKSSL_KEY`, `IPGEOLOCATION_TOKEN` (plus Azure-managed
  settings). Local equivalents go in `local.settings.json`, which is gitignored. `whois`
  needs no key at all — see below.
- **Best-effort external lookups (`geoip`, `whois`) must never surface as request errors.**
  Each owns a short, fixed timeout independent of the parent context's remaining deadline,
  and returns `nil` on any failure — a slow or dead upstream degrades the response, it
  never fails it. `geoip` uses 2s, one known-fast API host; `whois` uses a longer 3s
  (`lookupTimeout`) plus its own separate 5s bootstrap-warm budget (`bootstrapTimeout`),
  since it talks directly to whichever registry owns the TLD instead of one API host, and
  a cold IANA-registry fetch shouldn't eat into the per-lookup budget. Follow this pattern
  — short, fixed, failure-swallowing — for any new lookup in the same vein.
  Genuine failures (network error, non-200, undecodable body) are still logged at Error
  level via `slog` — silent to the caller, not silent to us; they reach Application
  Insights (importing the SDK's `sdk` package auto-installs the routing `slog` handler,
  so a plain `slog.ErrorContext` call is all a new lookup needs). Expected non-failures —
  no token configured, revocation's "couldn't determine" outcomes, `main.go`'s
  `resolve-failed`/`probe-failed` (already visible to the caller via `result.Error`) — are
  deliberately not logged, to keep the signal to genuine failures.
- **Two lookups, two auth schemes, and WHOIS uses none at all** — don't reach for the
  wrong one by habit: geolocation uses a `?apiKey=` query parameter; the function-key auth
  for `checkssl` is Azure's own platform mechanism; RDAP/WHOIS talk straight to whichever
  registry owns the TLD, with no key to send.
- **Bounded LRU caches**, one per lookup, keyed at the right granularity: `main.go`'s
  `resultsCache` (hostname, 500 entries, 24h), `geoip`'s (IP, 500, 7 days — IP-to-ASN/geo
  data changes slowly), `whois`'s (registrable domain, 500, 30 days — registration data
  barely changes day-to-day, and persistence via the durable Table Storage tier means a
  cold start doesn't have to re-query a registry for a domain this instance already
  resolved recently). Only successful lookups are cached, so a transient failure
  self-heals on the next request instead of being cached as a permanent miss. `main.go`'s
  `resultsCache` has one deliberate exception: a `private-use-host` result (IP literal or
  reserved TLD, from `ssrfguard.NeverPubliclyResolvable`) is cached too, because that verdict
  is a permanent fact about the hostname string, not a transient failure — unlike every
  other `result.Error` case, which stays uncached.
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
- **`whois/internal/{domain,model,rdap,srcerr,whoisclient}` are vendored from
  [who-dat](https://github.com/lissy93/who-dat), not written here.** Copied in (MIT
  licensed, `whois/internal/LICENSE-who-dat` carries the required notice) rather than
  imported as a module, because who-dat keeps this code under its own `internal/`
  package — Go's internal-import rule means only a copy works from outside that module.
  Every vendored file says so in its header comment. Two deliberate additions on top of
  upstream: `rdap.Client.WarmBootstrap` (so a cold IANA-registry fetch gets its own timeout
  budget, not the tighter per-lookup one — see `whois.go`'s `bootstrapTimeout` vs.
  `lookupTimeout`), and the port-43 client's package is renamed `whoisclient` (upstream
  calls it `whois`, which would collide with this repo's own top-level `whois` package).
  Don't "clean up" these files to match repo style beyond that — matching upstream verbatim
  is what makes a future re-vendor a clean diff. `whois.go` itself is this repo's code: it
  runs RDAP first, falls back to WHOIS on `srcerr.ErrNoSource`, maps the result onto the
  local `Info` shape, and applies this package's own cache (above) — deliberately *not*
  who-dat's own `internal/lookup`/`internal/cache`, which duplicate that.
- **`DetectedProviders` (the "DNS Provider" row) is this repo's own code, not who-dat's.**
  Neither RDAP nor WHOIS report a hosting/DNS provider label directly — who-dat's own
  hosted API doesn't compute one either. `whois.go`'s `nsProviderPatterns` is a small
  substring-match table over raw nameserver hostnames (e.g. `awsdns` → `aws-route53`,
  `cloudflare` → `cloudflare`) that reimplements what whoisjson.com (the now-retired
  third-party API this package used before) computed server-side. Extend the table, don't
  reach for an external lookup, when a new provider needs recognizing.
- A decoded `Info` with every field still empty is treated as no lookup at all (returns
  `nil`, uncached) rather than a "successful" empty result — the latter would otherwise
  freeze "no domain info" in the cache for the full 30-day TTL.
- **The backend owns issue metadata.** `issueCatalog` in `main.go` maps every issue code
  to its label and severity, and `setIssues` ships them per-result as `issueDetails`
  alongside the bare `issues` codes. The extension renders from `issueDetails` and treats
  its own JS maps as fallback only (for its client-side `no-https` code and rows cached
  before the field existed) — so **a new rule is a backend-only deploy**: add the catalog
  entry and the rule in `computeIssues`, never touch the extension maps. If a rule is
  time-based, also add its threshold-crossing instant to `resultTTL` as a **future-only**
  deadline (`futureDeadline`) — passing an already-crossed threshold into `cappedTTL`
  would floor virtually every mature result to the 5-minute minimum. This precedence
  extends into the extension's i18n layer too — see `issueInfo()` in popup.js/content.js
  below — and `_locales/en/messages.json` deliberately carries no `issue_*` keys so this
  invariant isn't silently broken for English users; see the extension i18n note below.
- **HTTP-level errors (bad request, rate limit, misconfiguration) carry a stable `errorCode`
  alongside the free-text `error` message**, for the same reason `issueDetails` gives issues
  a code separate from their label: `writeJSONError(w, status, code, msg)` in `main.go`
  writes `{"error": msg, "errorCode": code}` — current codes are `invalid-host`,
  `rate-limited`, `server-not-configured`. This is a distinct mechanism from `issueDetails`
  (these are raw non-200 HTTP responses that never become a `CheckResult` at all, e.g. the
  request never got as far as `performCheck`), but the client-side precedence is the same:
  `popup.js`'s `refresh()` translates by `errorCode` first, falls back to the backend's own
  `error` text, then a generic HTTP-status message. `background.js` never surfaces this body
  to the user (it just clears the toolbar badge/tooltip on a non-OK response), so only
  `popup.js` needs this wiring today.
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
- `lib/i18n.js` / `_locales/<lang>/messages.json` — UI chrome localization. Only the
  extension's own labels/buttons/verdicts translate; WHOIS, registrar, and issuer strings
  stay whatever language the source data is in. Issue labels are translated **by code**
  (`issue_<code with dashes turned to underscores>`), not by matching backend strings,
  because the code is the stable part. `issueInfo()`'s precedence is: locale message for
  this code (if non-empty) → the backend's `issueDetails` label → the local `ISSUE_LABELS`
  fallback → the raw code. Severity/level is **never** taken from locale files, only from
  the backend/local map — translation is a labeling concern, not a severity one.
  `_locales/en/messages.json` deliberately omits every `issue_*` key so English keeps
  reading straight from the backend catalog (see the note above) — add `issue_*` keys only
  in non-`en` locale files. `chrome.i18n` has no plural support, so counted strings
  (`$N$ issues found`, `$N$ certs`) use a manually-selected singular/plural key pair rather
  than one templated string — this doesn't cover languages with more than two plural forms
  (e.g. Russian's 1 / 2–4 / 5+), a known gap to revisit if it turns out to matter. Shipped
  locales today: `en` (baseline), `de`, `zh_CN`, `tr`, `ja`, `ru`, `fr`, `pt_BR` — every non-`en` file must
  carry all 57 `en` keys plus every `issue_*` key backend/main.go's `issueCatalog` defines
  (20 as of this writing), with every `$NAME$` placeholder token preserved verbatim; a quick
  Node script diffing `Object.keys()` against `en` (plus substring-checking each placeholder
  token) catches key-name/placeholder drift, but **not** a locale file merely lagging behind
  a newer backend issue code** — that only shows up as a code missing from all five locale
  files at once, which the pairwise diff-against-`en` never surfaces since `en` doesn't carry
  `issue_*` keys either. This was a real shipped gap: `revoked`/`weak-signature`/`weak-key`
  were added to `issueCatalog` after the locale files were generated, so all five fell
  through to the backend's raw English label for those three codes until caught by
  real-browser testing and fixed. When adding a new issue code to `issueCatalog`, add its
  `issue_<code>` translation to all five locale files in the same change — grep every locale
  file for the new code's key as a checklist, don't rely on the diff script alone.
  - **`chrome.i18n.getMessage()` is locked to the browser's own UI language** — there's no
    browser API to force a different one at runtime. The in-popup language switcher
    (`lib/i18n.js`, wired into the header's globe icon in `popup.js`) works around this by
    fetching the chosen locale's `messages.json` itself (`chrome.runtime.getURL(...)` +
    `fetch()`), caching the parsed object in `chrome.storage.local` as `uiMessagesOverride`
    (so `background.js`/`content.js` can read it back without re-fetching), and replicating
    chrome.i18n's own `$NAME$` placeholder substitution by hand against it. `t()` in
    `lib/i18n.js` checks this override first; `content.js` duplicates the identical logic
    inline (plain content script, can't `import`).
  - **A missing key under an active override must return `''`, never fall through to
    `chrome.i18n.getMessage()`.** That fallback is only correct in "auto" mode (no override —
    ordinary browser-language behavior, including chrome.i18n's own `default_locale`
    fallback chain). Once the user has explicitly picked a language, falling through to
    `chrome.i18n.getMessage()` would read the *browser's* actual UI language instead — e.g.
    picking "English" while Chrome itself is set to German would leak German text for every
    key the `en` file omits, which includes every `issue_*` key, by design. This was a
    real shipped bug during development; if you touch `t()` in `lib/i18n.js` or `content.js`,
    keep the override-active branch from ever reaching the `chrome.i18n.getMessage()` line.
  - **Fixed-width label columns (`.row .label` in `popup.css`, `.label` in `content.js`'s
    full-panel styles) truncate with `text-overflow: ellipsis` and carry a `title=` with the
    untruncated text** (set by `row()` in both files) — non-English labels can run
    meaningfully longer than their English source (German "Powered By" → "Bereitgestellt
    von", 18 chars vs. 12). Don't remove the ellipsis/`title` handling when touching these
    rows; a fixed-width column with no overflow handling reads fine in English and silently
    breaks in German/Russian/Turkish.

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
- **Third-party "view more" icons (ipinfo.io next to the IP address, ipinfo.io + Cloudflare
  Radar next to the ASN) are bundled locally as data: URIs, never hotlinked.** Each icon's
  source SVG lives in `icons/` (`ipinfo-pin.svg`, `cloudflare-icon.svg`) purely for
  provenance/regeneration; the actual `IPINFO_ICON_DATA_URI`/`CLOUDFLARE_ICON_DATA_URI`
  constants duplicated in `popup.js`/`content.js` are what's rendered. This avoids a live
  third-party image request on every popup open/panel render (consistent with the geo
  flag's own preference for an embedded `data:` URI) and sidesteps `web_accessible_resources`
  entirely, which would otherwise let any page fingerprint that this specific extension is
  installed by probing for its bundled resource. The shared `extLink(href, iconDataUri,
  title)` helper builds the `<a><img></a>` markup once per surface.

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

`CHECKSSL_KEY`, `IPGEOLOCATION_TOKEN` (plus whatever Azure itself
manages, e.g. `AzureWebJobsStorage`). `whois` needs no app setting — it talks to
registries directly, with no key. None of these are ever committed; they live only in
Azure app settings and, for local runs, `backend/local.settings.json` (gitignored).
