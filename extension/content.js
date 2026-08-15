// Always injected on https:// pages (see manifest.json content_scripts). Renders a
// draggable floating panel showing the current site's cert status, but only actually
// shows it when the user has floating view turned on (chrome.storage.local
// 'floatViewEnabled') — otherwise it just sits idle listening for that setting to change.
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

const HOST_ID = '__ssl_checker_float_host';
const COMPACT_OPACITY = 0.88; // fixed ~12% transparent

// Reloading the extension (e.g. during development) leaves this content script attached to
// any tab that was already open, but its chrome.* access gets invalidated — any subsequent
// call throws "Extension context invalidated". Checked before every chrome.* call below so
// a leftover script from a previous version just quietly stops instead of erroring.
function extensionAlive() {
  try {
    return !!(chrome.runtime && chrome.runtime.id);
  } catch (e) {
    return false;
  }
}

// Mirrors lib/i18n.js's override mechanism (see there for the full rationale): chrome.i18n
// is locked to the browser's own UI language, so a manually-picked language means checking
// this in-memory copy of the chosen locale's messages.json first. Seeded from
// chrome.storage.local by the initial storage.local.get(...) below and kept in sync by the
// storage.onChanged listener further down — this file can't import lib/i18n.js (plain
// content script, no modules), so the logic is duplicated rather than shared.
let overrideMessages = null;

function applyPlaceholders(message, placeholders, substitutions) {
  if (!placeholders) return message;
  const subs = substitutions ? (Array.isArray(substitutions) ? substitutions : [substitutions]) : [];
  let out = message;
  for (const [name, def] of Object.entries(placeholders)) {
    const m = /^\$(\d+)/.exec(def.content || '');
    const idx = m ? parseInt(m[1], 10) - 1 : 0;
    out = out.replace(new RegExp(`\\$${name.toUpperCase()}\\$`, 'g'), subs[idx] != null ? String(subs[idx]) : '');
  }
  return out;
}

// This is a plain (non-module) content script, so it can't import lib/i18n.js — the same
// tiny wrapper is duplicated here instead, guarded the same way every other chrome.* call
// in this file is: a dead extension context degrades to the backend/local-map label
// rather than throwing.
//
// Falling through to chrome.i18n.getMessage() is ONLY correct when no override is active
// (ordinary browser-language behavior) — see the matching comment on t() in lib/i18n.js for
// why a missing key under an active override must return '' instead of leaking the
// browser's actual UI language.
function t(key, substitutions) {
  if (!extensionAlive()) return '';
  try {
    if (overrideMessages) {
      const entry = overrideMessages[key];
      return entry && entry.message ? applyPlaceholders(entry.message, entry.placeholders, substitutions) : '';
    }
    return chrome.i18n.getMessage(key, substitutions) || '';
  } catch (e) {
    return '';
  }
}

let floatViewEnabled = false;
let compactMode = false;
const currentHostname = location.hostname; // fixed for this page's lifetime — never reassigned
let currentResult = null; // null while a check is still in flight

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = String(str);
  return div.innerHTML;
}

// Label/level for one issue code. Precedence: a locale translation for this code (if
// present) → the backend's issueDetails label (kept current without an extension update)
// → the local fallback map → the raw code. Levels always come from the backend/local map,
// never from locale files — severity isn't a translation concern.
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

// Darkened/muted versions of the full view's seal/verdict colors — same hue and saturation,
// just brought down to the lightness the user settled on for the warning tone, so they read
// as a subtle dark card tint rather than a bright indicator. 'checking' (no result yet) and
// 'info' share the grey since neither is a pass/fail signal.
const STATUS_RGB = {
  ok: '30,87,38',
  warning: '99,73,19',
  critical: '113,9,4',
  info: '54,58,64',
  checking: '54,58,64',
};

function sealGlyph(status) {
  switch (status) {
    case 'ok':
      return '✓';
    case 'warning':
      return '!';
    case 'critical':
      return '✕';
    default:
      return '?';
  }
}

function verdictText(r, status) {
  if (status === 'info') return r.error || t('verdict_could_not_fully_check');
  if (!r.issues || r.issues.length === 0) return t('verdict_no_issues');
  return r.issues.length === 1 ? t('verdict_issue_singular') : t('verdict_issues_plural', [String(r.issues.length)]);
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

function fmtChain(r) {
  if (!r.chainLength) return '—';
  const trust = r.chainVerified ? t('chain_trusted') : r.chainComplete ? t('chain_untrusted_root') : t('chain_incomplete');
  const certs = t(r.chainLength > 1 ? 'chain_certs_plural' : 'chain_certs_singular', [String(r.chainLength)]);
  return `${certs} · ${trust}`;
}

function row(label, value) {
  const safeLabel = escapeHtml(label);
  return `<div class="row"><span class="label" title="${safeLabel}">${safeLabel}</span><span class="value">${value}</span></div>`;
}

// A small icon linking out to a third-party site that has more detail on the value in this
// row (ipinfo.io, Cloudflare Radar). The icon is a locally-bundled data: URI, never a
// hotlinked remote image — see IPINFO_ICON_DATA_URI/CLOUDFLARE_ICON_DATA_URI above.
function extLink(href, iconDataUri, title) {
  const safeTitle = escapeHtml(title);
  return `<a class="ext-icon-link" href="${escapeHtml(href)}" target="_blank" rel="noopener noreferrer" title="${safeTitle}"><img class="ext-icon" src="${iconDataUri}" alt="${safeTitle}" /></a>`;
}

function ipRow(r) {
  if (!r.resolvedIP) return '';
  const ip = escapeHtml(r.resolvedIP);
  const value = `${ip} ${extLink(`https://ipinfo.io/${r.resolvedIP}`, IPINFO_ICON_DATA_URI, t('title_ipinfo_link'))}`;
  return row(t('label_ip_address'), value);
}

function networkRow(r) {
  if (!r.geoAsName && !r.geoAsn) return '';
  const asnNum = (r.geoAsn || '').replace(/^AS/i, '');
  const name = r.geoAsName ? escapeHtml(r.geoAsName) : '';
  const asnText = escapeHtml(r.geoAsn || '');
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
  return row(t('label_network'), `${base}${links}`);
}

// Flag rendering fallback chain: embedded data: URI (immune to COEP-isolated pages that
// block cross-origin <img> loads, e.g. web.whatsapp.com) → remote URL (older backend
// responses) → 2-letter country-code chip → nothing. The data-code attribute carries the
// code so attachFlagFallbacks can swap a failed <img> for the chip after render.
function flagHtml(r, cssClass) {
  const src = r.geoCountryFlagData || r.geoCountryFlag;
  const code = (r.geoCountryCode || '').toUpperCase();
  if (src) {
    return `<img class="${cssClass}" data-code="${escapeHtml(code)}" src="${escapeHtml(src)}" alt="" />`;
  }
  if (code) {
    return `<span class="flag-code">${escapeHtml(code)}</span>`;
  }
  return '';
}

// Inline onerror= attributes would be subject to the host page's CSP, so the handlers
// are attached programmatically after each render instead. The ext-icon-link images
// (ipinfo.io, Cloudflare) are bundled data: URIs and can't fail to load, so this only
// ever needs to handle the geo flag falling back to a country-code chip.
function attachFlagFallbacks(shadow) {
  shadow.querySelectorAll('img').forEach((img) => {
    img.addEventListener('error', () => {
      const code = img.dataset.code;
      if (code) {
        const chip = document.createElement('span');
        chip.className = 'flag-code';
        chip.textContent = code;
        img.replaceWith(chip);
      } else {
        img.remove();
      }
    });
  });
}

function locationRow(r) {
  if (!r.geoCountry) return '';
  const place = r.geoCity ? `${r.geoCity}, ${r.geoCountry}` : r.geoCountry;
  return row(t('label_location'), `${flagHtml(r, 'flag')}${escapeHtml(place)}`);
}

const SHARED_STYLES = `
  :host { all: initial; }
  .panel {
    font-family: -apple-system, "Segoe UI", Roboto, Arial, sans-serif;
    color: #e6edf3;
    background: #0d1117;
    border: 1px solid #262c36;
    border-radius: 10px;
    box-shadow: 0 8px 24px rgba(0,0,0,0.4);
    overflow: hidden;
    user-select: none;
    display: flex;
    flex-direction: column;
    max-height: calc(100vh - 32px);
  }
  .body {
    overflow-y: auto;
    overflow-x: hidden;
    min-height: 0;
    padding-bottom: 6px;
  }
  .iconbtn {
    flex: none; width: 22px; height: 22px; border: none; background: transparent;
    color: #8b949e; cursor: pointer; border-radius: 5px;
    display: flex; align-items: center; justify-content: center;
  }
  .iconbtn:hover { color: #a371f7; background: #161b22; }
  .iconbtn.close:hover { color: #f85149; }
  /* Buttons keep browser focus after a click (not just while hovered) — without this,
     the default focus outline reads as a highlight that's stuck "on" with the mouse
     nowhere near the button. :focus-visible still shows an indicator for keyboard use. */
  .iconbtn:focus { outline: none; }
  .iconbtn:focus-visible { outline: 2px solid rgba(255,255,255,0.4); outline-offset: 1px; }
  .muted-suffix { color: rgba(255,255,255,0.45); font-weight: 400; }
  .flag-code {
    flex: none; display: inline-block; padding: 1px 4px; margin-right: 6px;
    font-size: 9px; font-weight: 700; letter-spacing: 0.05em;
    color: rgba(255,255,255,0.85); background: rgba(255,255,255,0.15);
    border-radius: 3px; vertical-align: 1px;
  }
  .body::-webkit-scrollbar { width: 8px; }
  .body::-webkit-scrollbar-track { background: transparent; }
  .body::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.15); border-radius: 4px; }
  .body::-webkit-scrollbar-thumb:hover { background: rgba(255,255,255,0.28); }
`;

function removePanel() {
  const existing = document.getElementById(HOST_ID);
  if (existing) existing.remove();
}

function setCompact(value) {
  if (!extensionAlive()) return;
  chrome.storage.local.set({ floatViewCompact: value });
}

function turnOff() {
  if (extensionAlive()) chrome.storage.local.set({ floatViewEnabled: false });
  removePanel();
}

function attachDrag(host, handle, pos) {
  let dragging = false;
  let moved = false;
  let startX = 0;
  let startY = 0;
  let startLeft = pos.left;
  let startTop = pos.top;
  let curLeft = pos.left;
  let curTop = pos.top;

  handle.addEventListener('pointerdown', (e) => {
    // The handle may contain buttons/inputs (close, expand) — without this guard,
    // interacting with any of them also starts a drag (the pointerdown bubbles up to the
    // handle), and pointer-capture on the handle then swallows their own events.
    if (e.target.closest('button, input')) return;
    dragging = true;
    moved = false;
    startX = e.clientX;
    startY = e.clientY;
    startLeft = curLeft;
    startTop = curTop;
    handle.setPointerCapture(e.pointerId);
  });

  handle.addEventListener('pointermove', (e) => {
    if (!dragging) return;
    moved = true;
    curLeft = Math.max(0, Math.min(window.innerWidth - host.offsetWidth, startLeft + (e.clientX - startX)));
    curTop = Math.max(0, Math.min(window.innerHeight - 40, startTop + (e.clientY - startY)));
    host.style.left = curLeft + 'px';
    host.style.top = curTop + 'px';
  });

  handle.addEventListener('pointerup', (e) => {
    dragging = false;
    handle.releasePointerCapture(e.pointerId);
    // Only an actual move pins (and persists) a position — a plain click on the handle
    // must not freeze the default corner placement forever.
    if (!moved) return;
    window.__sslCheckerFloatPos = { left: curLeft, top: curTop };
    // Remember the placement across pages, tabs, and browser sessions.
    if (extensionAlive()) chrome.storage.local.set({ floatViewPos: window.__sslCheckerFloatPos });
  });
}

function renderPanel() {
  removePanel();
  if (!floatViewEnabled) return;

  const host = document.createElement('div');
  host.id = HOST_ID;
  host.style.all = 'initial';
  host.style.position = 'fixed';
  host.style.zIndex = '2147483647';
  const panelWidth = compactMode ? 250 : 300;
  const margin = 16;
  // Only an actual drag (see attachDrag's pointerup) should pin the panel to a fixed spot —
  // absent that, always recompute the top-right-corner default for the CURRENT width, so
  // switching compact (250px) <-> full (300px) re-hugs the corner instead of drifting from
  // a position that was only ever correct for the other width.
  const pos = window.__sslCheckerFloatPos
    ? {
        left: Math.max(0, Math.min(window.__sslCheckerFloatPos.left, window.innerWidth - panelWidth)),
        top: Math.max(0, Math.min(window.__sslCheckerFloatPos.top, window.innerHeight - 40)),
      }
    : { left: Math.max(0, window.innerWidth - panelWidth - margin), top: margin };
  host.style.left = pos.left + 'px';
  host.style.top = pos.top + 'px';
  document.documentElement.appendChild(host);

  const shadow = host.attachShadow({ mode: 'open' });

  if (compactMode) {
    renderCompact(host, shadow, pos);
  } else {
    renderFull(host, shadow, pos);
  }
}

function renderCompact(host, shadow, pos) {
  const r = currentResult;
  const status = r ? overallStatus(r) : 'checking';
  const bgRgb = STATUS_RGB[status] || STATUS_RGB.checking;

  shadow.innerHTML = `
    <style>
      ${SHARED_STYLES}
      .panel {
        position: relative;
        width: 250px;
        background: linear-gradient(160deg, rgba(${bgRgb},${COMPACT_OPACITY}), rgba(${bgRgb},${Math.max(COMPACT_OPACITY - 0.12, 0.4).toFixed(2)}));
        backdrop-filter: blur(14px) saturate(170%);
        -webkit-backdrop-filter: blur(14px) saturate(170%);
        border: 1px solid rgba(255,255,255,0.12);
      }
      .content { position: relative; padding: 10px 34px 10px 14px; cursor: grab; }
      .content:active { cursor: grabbing; }
      /* Rarely-needed chrome: hidden until the pointer is over the panel (or a button has
         keyboard focus), so the resting state is pure content. opacity (not display) keeps
         them clickable mid-fade and focusable for keyboard users. */
      .button-stack {
        position: absolute; top: 8px; right: 8px;
        display: flex; flex-direction: column; gap: 3px;
        opacity: 0; transition: opacity 0.15s;
      }
      .panel:hover .button-stack, .button-stack:focus-within { opacity: 1; }
      .iconbtn { color: rgba(255,255,255,0.7); }
      .iconbtn:hover { color: #fff; background: rgba(255,255,255,0.16); }
      .iconbtn.close:hover { color: #fff; background: rgba(248,81,73,0.4); }
      .header-line { display: flex; align-items: center; gap: 7px; margin-bottom: 5px; }
      .header-line .flag-code { margin-right: 0; }
      .glyph { flex: none; font-size: 11px; font-weight: 700; color: #fff; }
      .compact-flag {
        flex: none;
        width: 24px;
        height: auto;
        border-radius: 2px;
        box-shadow: 0 0 0 1px rgba(255, 255, 255, 0.25);
      }
      .city {
        flex: none; max-width: 45%; font-size: 10.5px; color: rgba(255,255,255,0.65);
        white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
      }
      .host {
        flex: 1; min-width: 0; font-size: 11px; font-weight: 600; color: rgba(255,255,255,0.85);
        white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
      }
      .row { display: flex; gap: 8px; padding: 3px 0; align-items: baseline; }
      .label {
        flex: none; width: 44px; color: rgba(255,255,255,0.55); font-size: 9.5px; font-weight: 700;
        text-transform: uppercase; letter-spacing: 0.06em;
        white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
      }
      .value {
        flex: 1; min-width: 0; font-size: 12px; font-weight: 600; color: #fff; line-height: 1.35;
        overflow: hidden; display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical;
      }
      .checking { font-size: 11.5px; color: rgba(255,255,255,0.75); }
    </style>
    <div class="panel">
      <div class="content" id="drag-handle">
        <div class="button-stack">
          <button class="iconbtn" id="expand-btn">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M15 3h6v6"/><path d="M9 21H3v-6"/><path d="M21 3l-7 7"/><path d="M3 21l7-7"/></svg>
          </button>
          <button class="iconbtn close" id="close-btn">✕</button>
        </div>
        <div class="header-line">
          <span class="glyph">${r ? sealGlyph(status) : '…'}</span>
          ${r ? flagHtml(r, 'compact-flag') : ''}
          ${r && r.geoCity ? `<span class="city">${escapeHtml(r.geoCity)} ·</span>` : ''}
          <span class="host">${escapeHtml(currentHostname)}</span>
        </div>
        ${
          r
            ? `<div class="rows">${row(t('label_org_short'), escapeHtml(r.org || '—'))}${row(t('label_issuer_short'), escapeHtml(r.issuerOrg || '—'))}</div>`
            : `<div class="checking">${escapeHtml(t('checking_compact'))}</div>`
        }
      </div>
    </div>
  `;

  const expandBtn = shadow.getElementById('expand-btn');
  expandBtn.title = t('title_expand');
  expandBtn.setAttribute('aria-label', t('title_expand'));
  expandBtn.addEventListener('click', () => setCompact(false));
  const closeBtn = shadow.getElementById('close-btn');
  closeBtn.title = t('title_float_view_hide');
  closeBtn.setAttribute('aria-label', t('title_float_view_hide'));
  closeBtn.addEventListener('click', turnOff);
  attachFlagFallbacks(shadow);

  attachDrag(host, shadow.getElementById('drag-handle'), pos);
}

function renderFull(host, shadow, pos) {
  const r = currentResult;
  const status = r ? overallStatus(r) : '';

  shadow.innerHTML = `
    <style>
      ${SHARED_STYLES}
      .panel {
        position: relative;
        width: 300px;
        background: linear-gradient(160deg, rgba(13,17,23,0.94), rgba(13,17,23,0.86));
        backdrop-filter: blur(14px) saturate(160%);
        -webkit-backdrop-filter: blur(14px) saturate(160%);
        border: 1px solid rgba(255,255,255,0.1);
      }
      .header { flex: none; display: flex; align-items: center; gap: 10px; padding: 12px 14px 8px; cursor: grab; }
      .header:active { cursor: grabbing; }
      /* The panel is user-select:none so dragging (by the header) never smears a text
         selection — but the body isn't a drag surface, so its content stays copyable. */
      .body { user-select: text; }
      .seal {
        flex: none; width: 30px; height: 30px; border-radius: 50%;
        border: 2px solid #8b949e; color: #8b949e;
        display: flex; align-items: center; justify-content: center;
        font-size: 14px; font-weight: 700;
      }
      .seal[data-status="ok"] { border-color: #3fb950; color: #3fb950; }
      .seal[data-status="warning"] { border-color: #d29922; color: #d29922; }
      .seal[data-status="critical"] { border-color: #f85149; color: #f85149; }
      .seal[data-status="info"] { border-color: #58a6ff; color: #58a6ff; }
      .titles { flex: 1; min-width: 0; }
      .hostname { font-weight: 600; font-size: 13px; word-break: break-all; }
      .verdict { margin-top: 2px; font-size: 11px; font-weight: 600; color: #8b949e; }
      .verdict.ok { color: #3fb950; }
      .verdict.warning { color: #d29922; }
      .verdict.critical { color: #f85149; }
      .verdict.info { color: #58a6ff; }
      .rows { padding: 2px 14px; }
      .row { display: flex; gap: 10px; padding: 5px 0; border-bottom: 1px solid #262c36; }
      .row:last-child { border-bottom: none; }
      .label { flex: none; width: 74px; color: #8b949e; font-size: 10px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
      .value { flex: 1; min-width: 0; overflow-wrap: break-word; font-size: 12px; font-family: ui-monospace, "SF Mono", Consolas, monospace; }
      .value a { color: #58a6ff; }
      .value a:hover { text-decoration: none; }
      .ext-icon-link { display: inline-flex; vertical-align: -2px; margin-left: 5px; opacity: 0.75; }
      .ext-icon-link:hover { opacity: 1; }
      .ext-icon { height: 13px; width: auto; max-width: 18px; border-radius: 1px; }
      .flag { height: auto; width: 24px; vertical-align: -3px; margin-right: 6px; }
      #issues { padding: 4px 14px; }
      .issue { padding: 6px 8px; margin-bottom: 6px; border-left: 3px solid #8b949e; background: #161b22; border-radius: 0 4px 4px 0; font-size: 12px; }
      .issue.critical { border-color: #f85149; }
      .issue.warning { border-color: #d29922; }
      .issue.info { border-color: #58a6ff; }
      details { margin: 6px 14px 10px; border-top: 1px solid #262c36; }
      summary { cursor: pointer; padding: 8px 0; font-size: 10.5px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; color: #8b949e; list-style: none; }
      summary::-webkit-details-marker { display: none; }
      summary::before { content: "▸ "; }
      details[open] summary::before { content: "▾ "; }
      .checking { padding: 4px 14px 14px; font-size: 12px; color: #8b949e; }
    </style>
    <div class="panel">
      <div class="header" id="drag-handle">
        <div class="seal" data-status="${status}">${r ? sealGlyph(status) : '…'}</div>
        <div class="titles">
          <div class="hostname">${escapeHtml(currentHostname)}</div>
          <div class="verdict ${status}">${r ? escapeHtml(verdictText(r, status)) : escapeHtml(t('checking_compact'))}</div>
        </div>
        <button class="iconbtn" id="compact-btn">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 14h6v6"/><path d="M20 10h-6V4"/><path d="M14 10l7-7"/><path d="M3 21l7-7"/></svg>
        </button>
        <button class="iconbtn close" id="close-btn">✕</button>
      </div>
      <div class="body">
      ${
        !r
          ? `<div class="checking">${escapeHtml(t('checking_full'))}</div>`
          : `
      ${
        r.org || r.protocol
          ? `<div class="rows">${row(t('label_organization'), escapeHtml(r.org || '—'))}${row(t('label_issuer'), escapeHtml(r.issuerOrg || '—'))}</div>`
          : ''
      }
      <div id="issues">${(r.issues || [])
        .map((i) => {
          const info = issueInfo(r, i);
          return `<div class="issue ${info.level}">${escapeHtml(info.label)}</div>`;
        })
        .join('')}</div>
      ${
        r.protocol || r.chainLength
          ? `<details>
              <summary>${escapeHtml(t('section_ssl'))}</summary>
              <div class="rows">
                ${row(t('label_protocol'), escapeHtml(`${r.protocol || '—'} ${r.cipherSuite || ''}`.trim()))}
                ${row(t('label_created'), fmtCreated(r.notBefore))}
                ${row(t('label_expires'), fmtExpires(r.notAfter))}
                ${row(t('label_chain'), escapeHtml(fmtChain(r)))}
                ${row(t('label_ocsp_stapled'), r.ocspStapled ? t('value_yes') : t('value_no'))}
                ${r.handshakeMs ? row(t('label_handshake'), `${r.handshakeMs} ms`) : ''}
                ${r.dnsNames && r.dnsNames.length ? row(t('label_covers'), escapeHtml(r.dnsNames.join(', '))) : ''}
              </div>
            </details>`
          : ''
      }
      ${
        r.protocol || r.chainLength || r.geoCountry || r.geoAsn || r.geoAsName || r.resolvedIP
          ? `<details>
              <summary>${escapeHtml(t('section_hosting'))}</summary>
              <div class="rows">
                ${r.protocol || r.chainLength ? row(t('label_server'), escapeHtml(r.server || t('value_not_disclosed'))) : ''}
                ${r.poweredBy ? row(t('label_powered_by'), escapeHtml(r.poweredBy)) : ''}
                ${r.protocol || r.chainLength ? row(t('label_http2'), r.http2 ? t('value_yes') : t('value_no')) : ''}
                ${ipRow(r)}
                ${locationRow(r)}
                ${networkRow(r)}
              </div>
            </details>`
          : ''
      }
      ${
        r.registrarName || r.domainCreated
          ? `<details>
              <summary>${escapeHtml(t('section_domain'))}</summary>
              <div class="rows">
                ${r.registrarName ? row(t('label_registrar'), escapeHtml(r.registrarName)) : ''}
                ${r.domainCreated ? row(t('label_created'), fmtCreated(r.domainCreated)) : ''}
                ${r.domainExpires ? row(t('label_expires'), fmtExpires(r.domainExpires)) : ''}
                ${r.dnsProviders && r.dnsProviders.length ? row(t('label_dns_provider'), escapeHtml(r.dnsProviders.join(', '))) : ''}
                ${r.ownerOrg ? row(t('label_owner'), escapeHtml(r.ownerOrg)) : ''}
              </div>
            </details>`
          : ''
      }`
      }
      </div>
    </div>
  `;

  const compactBtn = shadow.getElementById('compact-btn');
  compactBtn.title = t('title_compact_view');
  compactBtn.setAttribute('aria-label', t('title_compact_view'));
  compactBtn.addEventListener('click', () => setCompact(true));
  const closeBtnFull = shadow.getElementById('close-btn');
  closeBtnFull.title = t('title_float_view_hide');
  closeBtnFull.setAttribute('aria-label', t('title_float_view_hide'));
  closeBtnFull.addEventListener('click', turnOff);
  attachFlagFallbacks(shadow);

  attachDrag(host, shadow.getElementById('drag-handle'), pos);
}

function requestResult() {
  if (!extensionAlive()) return;
  try {
    chrome.runtime
      .sendMessage({ type: 'getResult' })
      .then((resp) => {
        // background's cached result can still be the *previous* page's for a moment after a
        // navigation (or a slow in-flight check for the old page can resolve after we've already
        // moved on) — only accept it if it's actually for this page, otherwise keep showing the
        // "Checking…" placeholder and wait for the sslResult message below instead.
        if (resp && resp.result && resp.hostname === currentHostname) {
          currentResult = resp.result;
          if (floatViewEnabled) renderPanel();
        }
      })
      .catch(() => {
        // background service worker not ready yet — sslResult message below will arrive once it is
      });
  } catch (e) {
    // extension context invalidated (e.g. a leftover script from before a dev reload)
  }
}

if (extensionAlive()) {
  chrome.storage.local
    .get(['floatViewEnabled', 'floatViewCompact', 'floatViewPos', 'uiMessagesOverride'])
    .then((stored) => {
      floatViewEnabled = !!stored.floatViewEnabled;
      compactMode = !!stored.floatViewCompact;
      overrideMessages = stored.uiMessagesOverride || null;
      // Restore the last dragged position (persisted across sessions). renderPanel clamps it
      // to the current viewport, so a spot saved on a large screen stays reachable on a
      // smaller one.
      const p = stored.floatViewPos;
      if (p && typeof p.left === 'number' && typeof p.top === 'number') {
        window.__sslCheckerFloatPos = p;
      }
      if (floatViewEnabled) {
        renderPanel(); // shows the "Checking…" placeholder immediately
        requestResult();
      }
    });
}

chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== 'local') return;
  let needsRender = false;

  if (changes.floatViewEnabled) {
    floatViewEnabled = !!changes.floatViewEnabled.newValue;
    needsRender = true;
    if (floatViewEnabled && !currentResult) requestResult();
  }
  if (changes.floatViewCompact) {
    compactMode = !!changes.floatViewCompact.newValue;
    needsRender = true;
  }
  if (changes.floatViewPos && changes.floatViewPos.newValue) {
    // A drag in one tab repositions the panel in every tab, so it's already in the
    // remembered spot when the user switches over.
    window.__sslCheckerFloatPos = changes.floatViewPos.newValue;
    needsRender = true;
  }
  if (changes.uiMessagesOverride) {
    // The popup's language switcher wrote a new (or cleared the) override — redraw the
    // panel in the newly-chosen language without needing a fresh result from the backend.
    overrideMessages = changes.uiMessagesOverride.newValue || null;
    needsRender = true;
  }

  if (needsRender) {
    if (floatViewEnabled) renderPanel();
    else removePanel();
  }
});

chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type !== 'sslResult' || msg.hostname !== currentHostname) return;
  currentResult = msg.result;
  if (floatViewEnabled) renderPanel();
});
