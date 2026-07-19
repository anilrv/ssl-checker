# Privacy Policy — SSL Issue Checker

_Last updated: 2026-07-19_

> This file mirrors the canonical policy served at
> <https://ssl-checker.anilrv.in/api/privacy> (authored in `backend/privacy.html`).
> If the two ever differ, the served page is authoritative.

SSL Issue Checker is a Chrome extension that checks the TLS/SSL certificate of the site in your active browser tab and reports its organization, issuer, validity, and any certificate issues, along with additional hosting and domain-registration details described below.

## What data this extension accesses

- **The hostname of your active tab** (e.g. `example.com`), read via Chrome's `tabs` permission, only for the site currently open in your browser.
- **Nothing else about the page** — not the full URL, path, query string, page content, form data, or browsing history.

## What this extension does with that data

- When you view a site or click the extension icon, **only the bare hostname** of the active tab (e.g. `example.com`, never the full URL) is sent to this extension's own backend — a service the developer operates at `ssl-checker.anilrv.in` — so it can perform a live TLS handshake against that hostname and report back what it finds.
- The backend returns certificate details (organization, issuer, validity dates, protocol, and any detected issues), which the extension displays in its popup and toolbar badge/tooltip.
- On first use, the extension also calls this same backend once to obtain an access token used to authenticate its own requests. No personal information is exchanged in that step.
- **No analytics, tracking, or advertising data collection** of any kind, and no data broker or third-party integrations.
- **Nothing is sold or shared** with any third party. The only network destination this extension ever talks to is its own backend, operated by the developer, solely to perform the certificate check you're requesting.
- If you turn on the optional **floating view**, the extension draws a small draggable panel directly on the page showing the same result already visible in the popup (organization, issuer, issues). This is rendered entirely on your device from data already fetched — nothing new is sent anywhere to show it, and it doesn't read or modify anything else on the page.

## Additional lookups performed by our backend

To show hosting and domain-registration details (server software, network/ASN, approximate server location, registrar, DNS provider) and to check certificate revocation, our backend — never the extension directly — makes further lookups against third-party services. These are public infrastructure/registration lookups about the _site's server, domain, or certificate_, not about you:

- **[ipgeolocation.io](https://ipgeolocation.io/)** — our backend sends the site's resolved server IP address to look up its approximate location (country/city) and network operator (ASN). Your own IP address is never sent to this or any other third party.
- **[whoisjson.com](https://whoisjson.com/)** — our backend sends the site's registrable domain name to look up public WHOIS registration data (registrar, registration/expiry dates, DNS provider, registered owner organization).
- **Certificate authority revocation services (OCSP/CRL)** — to check whether the site's certificate has been revoked, our backend queries the revocation endpoints published inside that certificate: the issuing certificate authority's OCSP responder and/or its certificate revocation list (CRL). Which authority receives the query depends on who issued the site's certificate (e.g. Let's Encrypt, DigiCert). The query identifies only the certificate being checked (its serial number and issuer), originates from our backend, and carries nothing about you, your browser, or your IP address.

These lookups are cached on our backend (server IPs for up to 7 days, domains for up to 30 days, CA revocation lists for up to 6 hours) purely to reduce repeat calls, and none of these services receive any information about you, your browser, or your IP address — only the hostname, IP, or certificate already being checked.

## Infrastructure and service providers

For full transparency, this service runs on the following infrastructure. None of these providers receive more than what's described, and none are used for analytics or advertising:

- **Microsoft Azure** — hosts the backend (an Azure Function). As the hosting platform it processes each request — the checked hostname and standard connection metadata — under Azure's own platform logging.
- **Cloudflare** — provides DNS for the backend's domain and proxies traffic to it. As a proxy it sees your IP address and the hostname being checked in transit, like any CDN, subject to Cloudflare's own privacy policy.
- **Cloudflare DNS and Google Public DNS (DNS-over-HTTPS)** — the backend resolves the checked site's hostname through these public resolvers before probing it. These queries originate from our backend, contain only the hostname being checked, and carry nothing about you, your browser, or your IP address.

## Where data is stored

- The extension stores its access token locally on your device via `chrome.storage.local` — this never leaves your device except when presented back to the backend to authenticate a check request.
- Whether you've turned floating view on or off is also stored locally via `chrome.storage.local`.
- The backend keeps a short-lived cache of recent check results and the lookups above (hostname/IP/domain and the resulting certificate, hosting, and registration metadata — up to 24 hours for check results, 7 days for network/location data, and 30 days for domain-registration data), purely to avoid re-checking the same site repeatedly. This cache is stored in Azure Table Storage under the same Microsoft Azure account already described in "Infrastructure and service providers" above, so it can survive the backend restarting. It is not tied to your identity, browser, or IP address, and there is no analytics or logging platform attached to it — only the same bounded cache described here.

## Permissions justification

| Permission | Why it's needed |
| --- | --- |
| `tabs` | To read the hostname of the active tab so it can be checked. |
| `storage` | To save the access token and your floating-view preference locally so they don't need to be re-fetched or re-set every time. |
| Content script on `https://*/*` | Draws the optional floating panel on the page when you turn floating view on, so it can follow you across normal browsing instead of disappearing on every page change. It stays inert (does nothing) unless you've explicitly turned floating view on. |

## Contact

Questions about this extension can be directed to the developer via the Chrome Web Store listing page.
