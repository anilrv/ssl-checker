# Privacy Policy — SSL Issue Checker

_Last updated: 2026-07-10_

SSL Issue Checker is a Chrome extension that checks the TLS/SSL certificate of the site in your active browser tab and reports its organization, issuer, validity, and any certificate issues.

## What data this extension accesses

- **The hostname of your active tab** (e.g. `example.com`), read via Chrome's `tabs` permission, only for the site currently open in your browser.
- **A backend URL and access key that you provide yourself**, stored via Chrome's `storage` permission. This extension does not ship with any backend built in — you deploy and control your own checking service (an Azure Function), and the extension is configured to talk to it.

## What this extension does with that data

- When you view a site or click the extension icon, the hostname of the active tab is sent to **the backend you configured** so it can perform a live certificate check against that hostname.
- The backend returns certificate details (organization, issuer, validity dates, protocol, and any detected issues), which the extension displays in its popup and toolbar badge/tooltip.
- **No full page URLs, page content, browsing history, or personal data are collected or transmitted** — only the bare hostname of the active tab.
- **No analytics, tracking, or advertising data collection** of any kind.
- **No data is sent to the extension's developer or any third party** — the only network destination is the backend URL you yourself configured in the extension's settings.

## Where data is stored

- Your configured backend URL and access key are stored locally via `chrome.storage.sync`, which Chrome syncs across your own signed-in browser instances. This data is never transmitted to the extension's developer.
- The backend you deploy may itself cache check results (e.g. certificate data, timestamps, usage counts) to avoid redundant checks — this is under your own control since you own and operate that backend.

## Permissions justification

| Permission | Why it's needed |
| --- | --- |
| `tabs` | To read the hostname of the active tab so it can be checked. |
| `storage` | To save the backend URL/key you configure, so you don't have to re-enter it every time. |
| Host permission for `https://*.azurewebsites.net/*` | To allow the extension to call the Azure Function backend you deploy and configure. |

## Contact

Questions about this extension can be directed to the developer via the Chrome Web Store listing page.
