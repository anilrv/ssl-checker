# Chrome Web Store listing draft — SSL Issue Checker

Paste these into the Developer Dashboard submission form; edit freely.

## Summary (short description, ≤132 chars)

Check the current site's TLS certificate — organization, issuer, validity, and issues like expired or self-signed certs.

## Detailed description

SSL Issue Checker inspects the TLS/SSL certificate of the site in your active tab and shows:

- The certificate's Organization and Issuer
- Validity dates (when it was issued, when it expires, with day counts)
- The negotiated TLS protocol and cipher suite
- Certificate chain completeness and trust status
- Flagged issues: expired, not-yet-valid, self-signed, hostname mismatch, incomplete certificate chain, untrusted root, and outdated (TLS 1.0) protocol support

This extension does a **live, real TLS handshake** to the site (not a cached third-party lookup), performed by a backend service the developer operates. No setup is required — the extension configures itself automatically on first use.

No browsing history, page content, or personal data is collected. Only the bare hostname of the active tab (never the full URL) is sent to the developer's backend to perform the check.

You can also turn on an optional floating view from the popup: a small draggable panel showing the same result (organization, issuer, issues), rendered on the page itself and following you across normal browsing until you turn it off.

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
