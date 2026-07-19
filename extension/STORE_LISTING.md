# Chrome Web Store listing draft — SSL Issue Checker

Paste these into the Developer Dashboard submission form; edit freely.

## Summary (short description, ≤132 chars)

Check the current site's TLS certificate — organization, issuer, validity, and issues like expired or self-signed certs.

## Detailed description

SSL Issue Checker inspects the TLS/SSL certificate of the site in your active tab — with a live, real TLS handshake, not a cached third-party lookup — and shows you everything that matters at a glance.

WHAT IT SHOWS

SSL / Certificate
• Organization and Issuer of the certificate
• Validity dates — when it was issued and when it expires, with friendly durations ("in 2m 20d")
• Negotiated TLS protocol and cipher suite
• Certificate chain length, completeness, and trust status
• OCSP stapling, TLS handshake time, and the hostnames the certificate covers

Hosting
• Server software (Server / X-Powered-By headers) and HTTP/2 support
• Approximate server location (city and country, with a flag)
• Network operator (ASN), linked to Cloudflare Radar

Domain
• Registrar and domain registration/expiry dates
• Detected DNS provider and registered owner organization

ISSUES, CALLED OUT CLEARLY

Expired or not-yet-valid certificates, self-signed certificates, hostname mismatches, incomplete certificate chains, untrusted roots, outdated TLS 1.0 support, and missing HTTPS. Domain-age warnings catch a common phishing pattern: a site whose domain was registered less than 10 days ago is flagged red, and less than 30 days ago yellow. You also get an early heads-up when the certificate — or the domain registration itself — is within 14 days of expiring. Every issue carries a severity level, summarized as a coloured badge on the toolbar icon.

TWO WAYS TO VIEW

• Toolbar popup — click the icon for the full breakdown, with a re-scan button.
• Optional floating panel — a small draggable card rendered on the page itself that follows you across normal browsing until you turn it off. It has a full mode and a compact mode (status, location flag, org and issuer at a glance), and it remembers where you placed it.

ZERO SETUP, MINIMAL DATA

No account, no API key, no configuration. Only the bare hostname of the active tab (never the full URL, never page content or history) is sent to the extension's own backend, which performs the check. No analytics, no tracking, no ads. Privacy policy: https://ssl-checker.anilrv.in/api/privacy

Useful for developers, site owners, and security-conscious users who want to see at a glance who issued a site's certificate, when it expires, and where the site is actually hosted.

## Category

Developer Tools

## Permission justifications

- **tabs**: reads the hostname of the currently active tab so its certificate can be checked. No other tab data (URLs, history, content) is accessed.
- **storage**: saves a short-lived access token and your floating-view on/off preference locally (via `chrome.storage.local`) so neither needs to be re-set every time.
- **Content script on `https://*/*`**: draws the optional floating view panel. It's present on every page but does nothing unless you've explicitly turned floating view on from the popup — it never reads or modifies page content, and only ever renders the same certificate result already shown in the popup.

No `host_permissions` are declared beyond what the content script's `matches` already covers, and the extension's `fetch()` calls to its backend rely on standard CORS cooperation from the server (which sets the appropriate `Access-Control-Allow-Origin` header for the extension's own origin).

## Privacy policy URL

https://ssl-checker.anilrv.in/api/privacy

Self-hosted on the same Azure Function as the backend — publicly accessible, no login required, permanent (doesn't depend on this conversation).
