import { getFunctionUrl, fetchFunctionKey, ensureFunctionKey, buildCheckUrl } from './lib/config.js';
import { t, loadStoredOverride, setLanguage, getStoredLanguage } from './lib/i18n.js';
import { SUPPORTED_LANGUAGES } from './lib/languages.js';

// Bundled locally (source SVG in icons/ipinfo-pin.svg) instead of hotlinking ipinfo.io's
// favicon — no third-party request just to show an icon next to the IP address row.
const IPINFO_ICON_DATA_URI =
  'data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4KPHN2ZyBpZD0iTGF5ZXJfMSIgZGF0YS1uYW1lPSJMYXllciAxIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA2MS43NSA3OC41MiI+CiAgPGRlZnM+CiAgICA8c3R5bGU+CiAgICAgIC5jbHMtMSB7CiAgICAgICAgZmlsbDogIzMwOTFjZjsKICAgICAgICBmaWxsLXJ1bGU6IGV2ZW5vZGQ7CiAgICAgICAgc3Ryb2tlLXdpZHRoOiAwcHg7CiAgICAgIH0KICAgIDwvc3R5bGU+CiAgPC9kZWZzPgogIDxwYXRoIGNsYXNzPSJjbHMtMSIgZD0iTTM0LjQ0LDU5LjE4bDUuMDksNS45NSw1Ljg4LTUuMTUsNS43Ni01LjA0YzYuMTktNS40NSw5Ljk5LTEzLjE1LDEwLjU4LTIxLjQyLjU5LTguMjctMi4wOC0xNi40NS03LjQzLTIyLjc0QzQ4LjkzLDQuNTIsNDEuMzIuNjgsMzMuMTQuMDhjLTguMTgtLjYtMTYuMjYsMi4xMS0yMi40OCw3LjUyQzQuNDcsMTMuMDQuNjcsMjAuNzUuMDgsMjkuMDJjLS41OSw4LjI3LDIuMDgsMTYuNDUsNy40MywyMi43NGwyMC4zMSwyMy43NGMxLjgxLDIuMTIsMy43Miw0LjQyLDYuNjcsMS45N2wuMDktLjA3LjA5LS4wOGMyLjgyLTIuNjEuODUtNC44NC0uOTctNi45N2wtMS4yNy0xLjQ4LTE5LjA0LTIyLjI3Yy00LTQuNzEtNi0xMC44My01LjU1LTE3LjAyLjQ0LTYuMTksMy4yOS0xMS45Niw3LjkxLTE2LjA0LDQuNjYtNC4wNSwxMC43MS02LjA2LDE2LjgzLTUuNjIsNi4xMi40NSwxMS44MiwzLjMyLDE1Ljg2LDgsNCw0LjcxLDYsMTAuODMsNS41NiwxNy4wMi0uNDQsNi4xOS0zLjI5LDExLjk2LTcuOTEsMTYuMDRsLTUuNzYsNS4wNC01LjA5LTUuOTUtNS4wOS01Ljk1LTQuOTgtNS44MmMtMS4zLTEuNTUtMS45NS0zLjU2LTEuOC01LjU5LjE1LTIuMDMsMS4wNy0zLjkyLDIuNTgtNS4yNywxLjU0LTEuMzIsMy41Mi0xLjk3LDUuNTMtMS44MiwyLjAxLjE1LDMuODgsMS4wOCw1LjIxLDIuNjEsMS4xMSwxLjMyLDEuNzUsMi45OCwxLjgyLDQuNzEuMDcsMS43My0uNDMsMy40NC0xLjQyLDQuODUtLjA1LjA3LS4wOS4xMy0uMTQuMTktLjUxLjc0LS43NSwxLjYyLS43MSwyLjUyLjA1LjkuMzgsMS43NS45NiwyLjQzLDIuNTYsMi45OSw1LjM4LjkzLDYuODgtMS42LDEuNjctMi44MiwyLjQzLTYuMSwyLjE2LTkuMzgtLjI3LTMuMjgtMS41NS02LjM4LTMuNjctOC44OC0yLjY4LTMuMS02LjQ3LTUuMDEtMTAuNTMtNS4zMS00LjA3LS4zLTguMDgsMS4wNC0xMS4xOCwzLjcyLTMuMDcsMi43MS00Ljk1LDYuNTQtNS4yNSwxMC42Ni0uMjksNC4xMSwxLjAzLDguMTcsMy42OCwxMS4zMWw0Ljk4LDUuODIsNS4wOSw1Ljk0LDUuMDksNS45NWgwWiIvPgo8L3N2Zz4=';

// Same rationale as IPINFO_ICON_DATA_URI: bundled locally (source SVG in
// icons/cloudflare-icon.svg) instead of hotlinking, used for the Cloudflare Radar ASN link
// in the Network row.
const CLOUDFLARE_ICON_DATA_URI =
  'data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0idXRmLTgiPz48c3ZnIHZlcnNpb249IjEuMSIgaWQ9IkxheWVyXzEiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyIgeG1sbnM6eGxpbms9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkveGxpbmsiIHg9IjBweCIgeT0iMHB4IiB2aWV3Qm94PSIwIDAgMTIyLjg4IDU1LjU3IiBzdHlsZT0iZW5hYmxlLWJhY2tncm91bmQ6bmV3IDAgMCAxMjIuODggNTUuNTciIHhtbDpzcGFjZT0icHJlc2VydmUiPjxzdHlsZSB0eXBlPSJ0ZXh0L2NzcyI+PCFbQ0RBVEFbDQoJLnN0MHtmaWxsOiNGNDgxMjA7fQ0KCS5zdDF7ZmlsbDojRkFBRDNGO30NCgkuc3Qye2ZpbGw6I0ZGRkZGRjt9DQpdXT48L3N0eWxlPjxnPjxwb2x5Z29uIGNsYXNzPSJzdDIiIHBvaW50cz0iMTEyLjY1LDMzLjAzIDk3LjIsMjQuMTcgOTQuNTQsMjMuMDEgMzEuMzMsMjMuNDUgMzEuMzMsNTUuNTMgMTEyLjY1LDU1LjUzIDExMi42NSwzMy4wMyIvPjxwYXRoIGNsYXNzPSJzdDAiIGQ9Ik04NC41Miw1Mi41OGMwLjc2LTIuNTksMC40Ny00Ljk3LTAuNzktNi43M2MtMS4xNS0xLjYyLTMuMS0yLjU2LTUuNDQtMi42N0wzMy45Niw0Mi42IGMtMC4yOSwwLTAuNTQtMC4xNC0wLjY4LTAuMzZjLTAuMTQtMC4yMS0wLjE4LTAuNS0wLjExLTAuNzljMC4xNC0wLjQzLDAuNTgtMC43NiwxLjA0LTAuNzlsNDQuNzMtMC41OCBjNS4yOS0wLjI1LDExLjA2LTQuNTQsMTMuMDctOS44bDIuNTYtNi42NmMwLjExLTAuMjksMC4xNC0wLjU4LDAuMDctMC44NkM5MS43Niw5LjcyLDgwLjEzLDAsNjYuMjMsMCBjLTEyLjgyLDAtMjMuNyw4LjI4LTI3LjU5LDE5Ljc3Yy0yLjUyLTEuODctNS43My0yLjg4LTkuMTgtMi41NmMtNi4xNiwwLjYxLTExLjA5LDUuNTUtMTEuNywxMS43Yy0wLjE0LDEuNTgtMC4wNCwzLjEzLDAuMzIsNC41NyBDOC4wMywzMy43OCwwLDQxLjk5LDAsNTIuMTFjMCwwLjksMC4wNywxLjgsMC4xOCwyLjdjMC4wNywwLjQzLDAuNDMsMC43NiwwLjg2LDAuNzZoODEuODJjMC40NywwLDAuOS0wLjMyLDEuMDQtMC43OUw4NC41Miw1Mi41OCBMODQuNTIsNTIuNTh6Ii8+PHBhdGggY2xhc3M9InN0MSIgZD0iTTk4LjY0LDI0LjA5Yy0wLjQsMC0wLjgzLDAtMS4yMiwwLjA0Yy0wLjI5LDAtMC41NCwwLjIyLTAuNjUsMC41bC0xLjczLDYuMDFjLTAuNzYsMi41OS0wLjQ3LDQuOTcsMC43OSw2LjczIGMxLjE1LDEuNjIsMy4xLDIuNTYsNS40NCwyLjY3bDkuNDQsMC41OGMwLjI5LDAsMC41NCwwLjE0LDAuNjgsMC4zNmMwLjE0LDAuMjIsMC4xOCwwLjU0LDAuMTEsMC43OSBjLTAuMTQsMC40My0wLjU4LDAuNzYtMS4wNCwwLjc5bC05LjgzLDAuNThjLTUuMzMsMC4yNS0xMS4wNiw0LjU0LTEzLjA3LDkuNzlsLTAuNzIsMS44NGMtMC4xNCwwLjM2LDAuMTEsMC43MiwwLjUsMC43MmgzMy43OCBjMC40LDAsMC43Ni0wLjI1LDAuODYtMC42NWMwLjU4LTIuMDksMC45LTQuMjksMC45LTYuNTVDMTIyLjg4LDM0Ljk3LDExMiwyNC4wOSw5OC42NCwyNC4wOUw5OC42NCwyNC4wOXoiLz48L2c+PC9zdmc+';

// Fallback only — the backend's issueDetails (issueCatalog in backend/main.go) is the
// authority for labels and levels, so new rules ship without an extension update. This
// map covers just the client-side 'no-https' code (no backend call happens for http://
// tabs) and cached rows written before issueDetails existed. Do NOT add new backend
// codes here; add them to the backend catalog instead.
const ISSUE_LABELS = {
  'no-https': { label: 'No HTTPS — connection is not encrypted', level: 'critical' },
  expired: { label: 'Certificate has expired', level: 'critical' },
  'not-yet-valid': { label: 'Certificate is not yet valid', level: 'critical' },
  'self-signed': { label: 'Certificate appears to be self-signed', level: 'critical' },
  'incomplete-chain': { label: 'Server is missing its intermediate certificate', level: 'warning' },
  'untrusted-chain': { label: "Chain doesn't lead to a trusted root CA", level: 'critical' },
  'hostname-mismatch': { label: "Certificate does not cover this site's hostname", level: 'critical' },
  'weak-protocol': { label: 'Server still accepts an outdated TLS protocol (TLS 1.0)', level: 'warning' },
  'recently-registered': { label: 'Domain was registered less than 10 days ago', level: 'critical' },
  'young-domain': { label: 'Domain was registered less than 30 days ago', level: 'warning' },
  'cert-expiring-soon': { label: 'Certificate expires within 14 days', level: 'warning' },
  'domain-expiring-soon': { label: 'Domain registration expires within 14 days', level: 'warning' },
  'resolve-failed': { label: 'Could not resolve this hostname', level: 'info' },
  'probe-failed': { label: 'Could not connect to check the certificate', level: 'info' },
};

const sealEl = document.getElementById('seal');
const sealGlyphEl = document.getElementById('seal-glyph');
const verdictEl = document.getElementById('verdict');
const rescanBtn = document.getElementById('rescan');
const floatViewBtn = document.getElementById('float-view');
const langSwitchBtn = document.getElementById('lang-switch');
const langWrapEl = document.getElementById('lang-wrap');
const langMenuEl = document.getElementById('lang-menu');
const techSummaryEl = document.querySelector('#tech summary');
const hostingSummaryEl = document.querySelector('#hosting summary');
const domainSummaryEl = document.querySelector('#domain summary');

// chrome.i18n.getMessage() is locked to the browser's own UI language — loadStoredOverride()
// seeds lib/i18n.js's in-memory override (if the user has manually picked a language via the
// lang-switch dropdown below) before anything below calls t(). A top-level await is safe here
// (unlike in background.js's service worker — see the comment there): this is a plain page
// script, not a persistent event-listener registration that Chrome needs synchronously.
await loadStoredOverride();

let floatViewUnavailable = false; // set once by disableFloatViewWhereUnavailable
let currentLanguageCode = await getStoredLanguage();

// popup.html's static markup (summaries, button titles) can't use __MSG_ substitution —
// that only works in manifest.json — so it's set here instead, both once on load and again
// after the user picks a new language from the lang-switch dropdown.
function applyStaticStrings() {
  rescanBtn.title = t('title_rescan');
  rescanBtn.setAttribute('aria-label', t('title_rescan'));
  langSwitchBtn.title = t('title_language_switch');
  langSwitchBtn.setAttribute('aria-label', t('title_language_switch'));
  techSummaryEl.textContent = t('section_ssl');
  hostingSummaryEl.textContent = t('section_hosting');
  domainSummaryEl.textContent = t('section_domain');
  if (floatViewUnavailable) {
    floatViewBtn.title = t('title_float_view_unavailable');
  } else {
    setFloatViewButtonState(floatViewBtn.classList.contains('active'));
  }
}
applyStaticStrings();

async function getActiveTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

// Calendar-aware year/month/day breakdown between two instants (not a naive
// day-count/30/365 division, which drifts and can produce nonsense like "12m").
function durationParts(fromMs, toMs) {
  const from = new Date(fromMs);
  const to = new Date(toMs);
  let y = to.getFullYear() - from.getFullYear();
  let m = to.getMonth() - from.getMonth();
  let d = to.getDate() - from.getDate();
  if (d < 0) {
    m -= 1;
    d += new Date(to.getFullYear(), to.getMonth(), 0).getDate();
  }
  if (m < 0) {
    y -= 1;
    m += 12;
  }
  return { y, m, d };
}

function formatDuration(y, m, d) {
  const parts = [];
  if (y > 0) parts.push(`${y}y`);
  if (m > 0) parts.push(`${m}m`);
  if (d > 0 || parts.length === 0) parts.push(`${d}d`);
  return parts.slice(0, 2).join(' ');
}

// Returns pre-built safe HTML (dateStr is locale-formatted digits/punctuation, the
// duration is our own digit+letter formatter — nothing derived from untrusted input),
// so callers pass this straight into row() rather than through escapeHtml.
// The y/m/d duration shorthand itself is deliberately not localized (see formatDuration) —
// only the surrounding row labels are translated, not this compact date math.
function fmtCreated(epochSeconds) {
  if (!epochSeconds) return '—';
  const createdMs = epochSeconds * 1000;
  const dateStr = new Date(createdMs).toLocaleDateString();
  const now = Date.now();
  if (createdMs > now) return dateStr;
  const { y, m, d } = durationParts(createdMs, now);
  return `${dateStr} <span class="muted-suffix">(${formatDuration(y, m, d)} ago)</span>`;
}

function fmtExpires(epochSeconds) {
  if (!epochSeconds) return '—';
  const expiresMs = epochSeconds * 1000;
  const dateStr = new Date(expiresMs).toLocaleDateString();
  const now = Date.now();
  if (expiresMs < now) {
    const { y, m, d } = durationParts(expiresMs, now);
    return `${dateStr} <span class="muted-suffix">(expired ${formatDuration(y, m, d)} ago)</span>`;
  }
  const { y, m, d } = durationParts(now, expiresMs);
  return `${dateStr} <span class="muted-suffix">(in ${formatDuration(y, m, d)})</span>`;
}

function fmtChain(result) {
  if (!result.chainLength) return '—';
  const trust = result.chainVerified
    ? t('chain_trusted')
    : result.chainComplete
      ? t('chain_untrusted_root')
      : t('chain_incomplete');
  const certs = t(result.chainLength > 1 ? 'chain_certs_plural' : 'chain_certs_singular', [String(result.chainLength)]);
  return `${certs} · ${trust}`;
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = String(str);
  return div.innerHTML;
}

// Label/level for one issue code. Precedence: a locale translation for this code (if
// present) → the backend's issueDetails label (issueCatalog in backend/main.go, kept
// current without an extension update) → the local fallback map → the raw code. Levels
// always come from the backend/local map, never from locale files — severity isn't a
// translation concern.
//
// _locales/en/messages.json deliberately has NO issue_* keys: English already comes
// straight from the backend, so defining them there would shadow every future wording
// change to issueCatalog for English users forever. issue_* keys belong only in non-en
// locale files.
function issueInfo(result, code) {
  const fromBackend = ((result && result.issueDetails) || []).find((d) => d.code === code);
  const fallback = ISSUE_LABELS[code];
  const level = (fromBackend && fromBackend.level) || (fallback && fallback.level) || 'warning';
  const localized = t(`issue_${code.replace(/-/g, '_')}`);
  const label = localized || (fromBackend && fromBackend.label) || (fallback && fallback.label) || code;
  return { label, level };
}

function overallStatus(result) {
  const issues = (result && result.issues) || [];
  if (issues.length === 0) return 'ok';
  const levels = issues.map((i) => issueInfo(result, i).level);
  if (levels.includes('critical')) return 'critical';
  if (levels.includes('warning')) return 'warning';
  return 'info';
}

function sealGlyph(status) {
  switch (status) {
    case 'ok':
      return '✓'; // check
    case 'warning':
      return '!';
    case 'critical':
      return '✕'; // x
    default:
      return '?';
  }
}

function verdictText(result, status) {
  if (status === 'info') return result.error || t('verdict_could_not_fully_check');
  if (!result.issues || result.issues.length === 0) return t('verdict_no_issues');
  return result.issues.length === 1
    ? t('verdict_issue_singular')
    : t('verdict_issues_plural', [String(result.issues.length)]);
}

function row(label, value, extraClass) {
  const safeLabel = escapeHtml(label);
  return `<div class="row"><span class="label" title="${safeLabel}">${safeLabel}</span><span class="value${extraClass ? ' ' + extraClass : ''}">${value}</span></div>`;
}

// A small icon linking out to a third-party site that has more detail on the value in this
// row (ipinfo.io, Cloudflare Radar). The icon is a locally-bundled data: URI, never a
// hotlinked remote image — see IPINFO_ICON_DATA_URI/CLOUDFLARE_ICON_DATA_URI above.
function extLink(href, iconDataUri, title) {
  const safeTitle = escapeHtml(title);
  return `<a class="ext-icon-link" href="${escapeHtml(href)}" target="_blank" rel="noopener noreferrer" title="${safeTitle}"><img class="ext-icon" src="${iconDataUri}" alt="${safeTitle}" /></a>`;
}

function ipRow(result) {
  if (!result.resolvedIP) return '';
  const ip = escapeHtml(result.resolvedIP);
  const value = `${ip} ${extLink(`https://ipinfo.io/${result.resolvedIP}`, IPINFO_ICON_DATA_URI, t('title_ipinfo_link'))}`;
  return row(t('label_ip_address'), value, 'mono');
}

function networkRow(result) {
  if (!result.geoAsName && !result.geoAsn) return '';
  const asnNum = (result.geoAsn || '').replace(/^AS/i, '');
  const name = result.geoAsName ? escapeHtml(result.geoAsName) : '';
  const asnText = escapeHtml(result.geoAsn || '');
  const base = name && asnText ? `${name} (${asnText})` : name || asnText;
  // The ASN itself is plain text now — two small icon links (ipinfo.io, Cloudflare Radar)
  // sit after it instead of making the ASN text itself a link, so both destinations are
  // equally reachable rather than picking one to "win" the hyperlink.
  const links = asnNum
    ? extLink(`https://ipinfo.io/AS${encodeURIComponent(asnNum)}`, IPINFO_ICON_DATA_URI, t('title_ipinfo_link')) +
      extLink(
        `https://radar.cloudflare.com/asn/${encodeURIComponent(asnNum)}`,
        CLOUDFLARE_ICON_DATA_URI,
        t('title_cloudflare_radar_link')
      )
    : '';
  return row(t('label_network'), `${base}${links}`, 'mono');
}

function locationRow(result) {
  if (!result.geoCountry) return '';
  const place = result.geoCity ? `${result.geoCity}, ${result.geoCountry}` : result.geoCountry;
  // Prefer the backend-embedded data: URI (no third-party request from the popup at
  // all); fall back to the remote URL for older cached responses, then to a 2-letter
  // country-code chip if there's no image.
  const src = result.geoCountryFlagData || result.geoCountryFlag;
  const code = (result.geoCountryCode || '').toUpperCase();
  let flag = '';
  if (src) {
    flag = `<img class="flag" src="${escapeHtml(src)}" alt="" />`;
  } else if (code) {
    flag = `<span class="flag-code">${escapeHtml(code)}</span>`;
  }
  return row(t('label_location'), `${flag}${escapeHtml(place)}`, 'mono');
}

// Remembered so a language change can redraw the current result in the new language without
// a redundant network round-trip — the backend data hasn't changed, only which language it's
// being read in.
let lastTab = null;
let lastResult = null;

function render(tab, result) {
  lastTab = tab;
  lastResult = result;

  const hostnameEl = document.getElementById('hostname');
  const identityEl = document.getElementById('identity');
  const issuesEl = document.getElementById('issues');
  const techRowsEl = document.getElementById('tech-rows');
  const techEl = document.getElementById('tech');
  const hostingRowsEl = document.getElementById('hosting-rows');
  const hostingEl = document.getElementById('hosting');
  const domainRowsEl = document.getElementById('domain-rows');
  const domainEl = document.getElementById('domain');

  let hostname = '—';
  try {
    hostname = tab && tab.url ? new URL(tab.url).hostname : '—';
  } catch (e) {
    // ignore (chrome:// pages etc.)
  }
  hostnameEl.textContent = hostname;

  if (!result) {
    sealEl.dataset.status = '';
    sealGlyphEl.textContent = '';
    verdictEl.className = '';
    verdictEl.textContent = t('verdict_no_scan_data');
    identityEl.innerHTML = '';
    issuesEl.innerHTML = '';
    techRowsEl.innerHTML = '';
    techEl.style.display = 'none';
    hostingRowsEl.innerHTML = '';
    hostingEl.style.display = 'none';
    domainRowsEl.innerHTML = '';
    domainEl.style.display = 'none';
    return;
  }

  // A client-side failure (backend unreachable, key rejected, non-OK response) arrives as
  // { issues: [], error } — without this branch, empty issues would read as 'ok' and the
  // popup would show a green "No issues found" for a check that never happened.
  const status =
    result.error && (!result.issues || result.issues.length === 0)
      ? 'info'
      : overallStatus(result);
  sealEl.dataset.status = status;
  sealGlyphEl.textContent = sealGlyph(status);
  sealEl.classList.remove('stamp');
  void sealEl.offsetWidth; // restart animation
  sealEl.classList.add('stamp');

  verdictEl.className = status;
  verdictEl.textContent = verdictText(result, status);

  if (result.org || result.protocol) {
    identityEl.innerHTML =
      row(t('label_organization'), escapeHtml(result.org || '—'), 'mono') +
      row(t('label_issuer'), escapeHtml(result.issuerOrg || '—'), 'mono');
  } else {
    identityEl.innerHTML = '';
  }

  const issues = result.issues || [];
  issuesEl.innerHTML = issues
    .map((i) => {
      const info = issueInfo(result, i);
      return `<div class="issue ${info.level}">${escapeHtml(info.label)}</div>`;
    })
    .join('');

  const hasProbe = result.protocol || result.chainLength;

  if (hasProbe) {
    techEl.style.display = '';
    techRowsEl.innerHTML =
      row(t('label_protocol'), escapeHtml(`${result.protocol || '—'} ${result.cipherSuite || ''}`.trim()), 'mono') +
      row(t('label_created'), fmtCreated(result.notBefore), 'mono') +
      row(t('label_expires'), fmtExpires(result.notAfter), 'mono') +
      row(t('label_chain'), escapeHtml(fmtChain(result)), 'mono') +
      row(t('label_ocsp_stapled'), result.ocspStapled ? t('value_yes') : t('value_no'), 'mono') +
      (result.handshakeMs ? row(t('label_handshake'), `${result.handshakeMs} ms`, 'mono') : '') +
      (result.dnsNames && result.dnsNames.length
        ? row(t('label_covers'), escapeHtml(result.dnsNames.join(', ')), 'mono')
        : '');
  } else {
    techEl.style.display = 'none';
    techRowsEl.innerHTML = '';
  }

  const hasHosting = hasProbe || result.geoCountry || result.geoAsn || result.geoAsName || result.resolvedIP;
  if (hasHosting) {
    hostingEl.style.display = '';
    hostingRowsEl.innerHTML =
      (hasProbe ? row(t('label_server'), escapeHtml(result.server || t('value_not_disclosed')), 'mono') : '') +
      (result.poweredBy ? row(t('label_powered_by'), escapeHtml(result.poweredBy), 'mono') : '') +
      (hasProbe ? row(t('label_http2'), result.http2 ? t('value_yes') : t('value_no'), 'mono') : '') +
      ipRow(result) +
      locationRow(result) +
      networkRow(result);
  } else {
    hostingEl.style.display = 'none';
    hostingRowsEl.innerHTML = '';
  }

  if (result.registrarName || result.domainCreated) {
    domainEl.style.display = '';
    domainRowsEl.innerHTML =
      (result.registrarName ? row(t('label_registrar'), escapeHtml(result.registrarName), 'mono') : '') +
      (result.domainCreated ? row(t('label_created'), fmtCreated(result.domainCreated), 'mono') : '') +
      (result.domainExpires ? row(t('label_expires'), fmtExpires(result.domainExpires), 'mono') : '') +
      (result.dnsProviders && result.dnsProviders.length
        ? row(t('label_dns_provider'), escapeHtml(result.dnsProviders.join(', ')), 'mono')
        : '') +
      (result.ownerOrg ? row(t('label_owner'), escapeHtml(result.ownerOrg), 'mono') : '');
  } else {
    domainEl.style.display = 'none';
    domainRowsEl.innerHTML = '';
  }
}

async function refresh(force) {
  const tab = await getActiveTab();
  if (!tab) return;

  let hostname;
  try {
    hostname = new URL(tab.url).hostname;
  } catch (e) {
    render(tab, null);
    return;
  }

  const functionUrl = await getFunctionUrl();
  let functionKey;
  try {
    functionKey = await ensureFunctionKey();
  } catch (e) {
    render(tab, { issues: [], error: t('error_could_not_reach_service', [e.message]) });
    return;
  }

  if (force) rescanBtn.classList.add('spinning');

  try {
    let resp = await fetch(buildCheckUrl(functionUrl, hostname, { force, key: functionKey }));
    if (resp.status === 401 || resp.status === 403) {
      try {
        functionKey = await fetchFunctionKey();
        resp = await fetch(buildCheckUrl(functionUrl, hostname, { force, key: functionKey }));
      } catch (e) {
        // bootstrap unreachable — fall through to the stale 401/403 response below
      }
    }
    if (resp.status === 401 || resp.status === 403) {
      render(tab, { issues: [], error: t('error_function_key_rejected') });
      return;
    }
    if (!resp.ok) {
      // e.g. 429 rate limit or 400 — the body is {"error": msg, "errorCode": code}, not a
      // CheckResult; rendering it as one would show a false "No issues found". errorCode is
      // a stable identifier (writeJSONError in backend/main.go) the extension can translate
      // by code — same locale-message-wins-over-backend-text precedence as issueInfo().
      let msg = t('error_check_failed', [String(resp.status)]);
      try {
        const body = await resp.json();
        if (body) {
          const localized = body.errorCode ? t(`error_code_${body.errorCode.replace(/-/g, '_')}`) : '';
          msg = localized || body.error || msg;
        }
      } catch (e) {
        // non-JSON error body — keep the generic message
      }
      render(tab, { issues: [], error: msg });
      return;
    }
    const result = await resp.json();
    render(tab, result);
  } catch (e) {
    render(tab, { issues: [], error: t('error_could_not_reach_service', [e.message]) });
  } finally {
    rescanBtn.classList.remove('spinning');
  }
}

rescanBtn.addEventListener('click', () => refresh(true));

// The actual panel is rendered by content.js, which is always present on https:// pages
// and follows the 'floatViewEnabled' storage flag across navigation. This button just
// flips that flag — no chrome.scripting call needed from here at all.
function setFloatViewButtonState(enabled) {
  floatViewBtn.classList.toggle('active', enabled);
  floatViewBtn.title = enabled ? t('title_float_view_hide') : t('title_float_view_show');
}

floatViewBtn.addEventListener('click', async () => {
  const { floatViewEnabled } = await chrome.storage.local.get('floatViewEnabled');
  const next = !floatViewEnabled;
  await chrome.storage.local.set({ floatViewEnabled: next });
  window.close();
});

chrome.storage.local.get('floatViewEnabled').then(({ floatViewEnabled }) => {
  setFloatViewButtonState(!!floatViewEnabled);
});

// Chrome forbids content scripts on the Web Store (and non-https pages never match the
// content script), so the floating panel can't exist there — disable the toggle with an
// explanation instead of letting it look broken.
(async function disableFloatViewWhereUnavailable() {
  const tab = await getActiveTab();
  let unavailable = true;
  try {
    const u = new URL(tab.url);
    unavailable =
      u.protocol !== 'https:' ||
      u.hostname === 'chromewebstore.google.com' ||
      u.hostname === 'chrome.google.com';
  } catch (e) {
    // unparseable URL (chrome:// pages etc.) — leave unavailable
  }
  if (unavailable) {
    floatViewBtn.disabled = true;
    floatViewUnavailable = true;
    floatViewBtn.title = t('title_float_view_unavailable');
  }
})();

// Language switcher: chrome.i18n has no API to force a locale at runtime, so picking one
// here means loading its messages.json ourselves (see lib/i18n.js) and redrawing everything
// that reads t() — the backend result itself is unaffected, so this never re-fetches it.
function renderLangMenu() {
  langMenuEl.innerHTML = SUPPORTED_LANGUAGES.map(({ code, name }) => {
    const label = code === 'auto' ? t('language_auto') : name;
    const active = code === currentLanguageCode;
    return (
      `<button class="lang-option${active ? ' active' : ''}" data-code="${code}" role="menuitemradio" aria-checked="${active}">` +
      `<span class="check">✓</span>${escapeHtml(label)}</button>`
    );
  }).join('');
}

function openLangMenu() {
  langMenuEl.hidden = false;
  langSwitchBtn.setAttribute('aria-expanded', 'true');
}

function closeLangMenu() {
  langMenuEl.hidden = true;
  langSwitchBtn.setAttribute('aria-expanded', 'false');
}

langSwitchBtn.addEventListener('click', (e) => {
  e.stopPropagation();
  if (langMenuEl.hidden) openLangMenu();
  else closeLangMenu();
});

langMenuEl.addEventListener('click', async (e) => {
  const btn = e.target.closest('.lang-option');
  if (!btn) return;
  closeLangMenu();
  const code = btn.dataset.code;
  if (code === currentLanguageCode) return;
  currentLanguageCode = code;
  await setLanguage(code);
  applyStaticStrings();
  renderLangMenu();
  render(lastTab, lastResult);
});

document.addEventListener('click', (e) => {
  if (!langMenuEl.hidden && !langWrapEl.contains(e.target)) closeLangMenu();
});

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && !langMenuEl.hidden) {
    closeLangMenu();
    langSwitchBtn.focus();
  }
});

renderLangMenu();

// The popup can stay open across a same-tab navigation (typing a new URL, clicking a
// link, back/forward) — without this listener it would keep showing the previous
// site's result even though the active tab has moved on.
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (!tab.active) return;
  if (changeInfo.url || changeInfo.status === 'complete') {
    refresh(false);
  }
});

(async function init() {
  refresh(false);
})();
