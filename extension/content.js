// Always injected on https:// pages (see manifest.json content_scripts). Renders a
// draggable floating panel showing the current site's cert status, but only actually
// shows it when the user has floating view turned on (chrome.storage.local
// 'floatViewEnabled') — otherwise it just sits idle listening for that setting to change.

const ISSUE_LABELS = {
  'no-https': { label: 'No HTTPS — connection is not encrypted', level: 'critical' },
  expired: { label: 'Certificate has expired', level: 'critical' },
  'not-yet-valid': { label: 'Certificate is not yet valid', level: 'critical' },
  'self-signed': { label: 'Certificate appears to be self-signed', level: 'critical' },
  'incomplete-chain': { label: 'Server is missing its intermediate certificate', level: 'warning' },
  'untrusted-chain': { label: "Chain doesn't lead to a trusted root CA", level: 'critical' },
  'hostname-mismatch': { label: "Certificate does not cover this site's hostname", level: 'critical' },
  'weak-protocol': { label: 'Server still accepts an outdated TLS protocol (TLS 1.0)', level: 'warning' },
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

let floatViewEnabled = false;
let compactMode = false;
const currentHostname = location.hostname; // fixed for this page's lifetime — never reassigned
let currentResult = null; // null while a check is still in flight

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = String(str);
  return div.innerHTML;
}

function severityOf(issue) {
  return (ISSUE_LABELS[issue] || {}).level || 'warning';
}

function overallStatus(issues) {
  if (!issues || issues.length === 0) return 'ok';
  const levels = issues.map(severityOf);
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
  if (status === 'info') return r.error || 'Could not fully check this site';
  if (!r.issues || r.issues.length === 0) return 'No issues found';
  return `${r.issues.length} issue${r.issues.length > 1 ? 's' : ''} found`;
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
  const trust = r.chainVerified ? 'trusted' : r.chainComplete ? 'untrusted root' : 'incomplete';
  return `${r.chainLength} cert${r.chainLength > 1 ? 's' : ''} · ${trust}`;
}

function row(label, value) {
  return `<div class="row"><span class="label">${escapeHtml(label)}</span><span class="value">${value}</span></div>`;
}

function networkRow(r) {
  if (!r.geoAsName && !r.geoAsn) return '';
  const asnNum = (r.geoAsn || '').replace(/^AS/i, '');
  const asnLink = asnNum
    ? `<a href="https://radar.cloudflare.com/asn/${encodeURIComponent(asnNum)}" target="_blank" rel="noopener noreferrer">${escapeHtml(r.geoAsn)}</a>`
    : escapeHtml(r.geoAsn || '');
  const name = r.geoAsName ? escapeHtml(r.geoAsName) : '';
  const value = name && asnNum ? `${name} (${asnLink})` : name || asnLink;
  return row('Network', value);
}

function locationRow(r) {
  if (!r.geoCountry) return '';
  const place = r.geoCity ? `${r.geoCity}, ${r.geoCountry}` : r.geoCountry;
  const flag = r.geoCountryFlag
    ? `<img class="flag" src="${escapeHtml(r.geoCountryFlag)}" alt="" />`
    : '';
  return row('Location', `${flag}${escapeHtml(place)}`);
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
  let startX = 0;
  let startY = 0;
  let startLeft = pos.left;
  let startTop = pos.top;
  let curLeft = pos.left;
  let curTop = pos.top;

  handle.addEventListener('pointerdown', (e) => {
    // The handle may contain buttons/inputs (close, expand, opacity slider) — without this
    // guard, interacting with any of them also starts a drag (the pointerdown bubbles up
    // to the handle), and pointer-capture on the handle then swallows their own events.
    if (e.target.closest('button, input')) return;
    dragging = true;
    startX = e.clientX;
    startY = e.clientY;
    startLeft = curLeft;
    startTop = curTop;
    handle.setPointerCapture(e.pointerId);
  });

  handle.addEventListener('pointermove', (e) => {
    if (!dragging) return;
    curLeft = Math.max(0, Math.min(window.innerWidth - host.offsetWidth, startLeft + (e.clientX - startX)));
    curTop = Math.max(0, Math.min(window.innerHeight - 40, startTop + (e.clientY - startY)));
    host.style.left = curLeft + 'px';
    host.style.top = curTop + 'px';
  });

  handle.addEventListener('pointerup', (e) => {
    dragging = false;
    handle.releasePointerCapture(e.pointerId);
    window.__sslCheckerFloatPos = { left: curLeft, top: curTop };
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
  const status = r ? overallStatus(r.issues) : 'checking';
  const bgRgb = STATUS_RGB[status] || STATUS_RGB.checking;
  const tooltipParts = [];
  if (r && r.geoCountry) tooltipParts.push(r.geoCountry);
  if (r && r.dnsProviders && r.dnsProviders.length) tooltipParts.push(r.dnsProviders.join(', '));
  const tooltipAttr = tooltipParts.length ? ` title="${escapeHtml(tooltipParts.join(' · '))}"` : '';
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
      .content { position: relative; padding: 12px 34px 12px 16px; cursor: grab; }
      .content:active { cursor: grabbing; }
      .button-stack {
        position: absolute; top: 8px; right: 8px;
        display: flex; flex-direction: column; gap: 3px;
      }
      .iconbtn { color: rgba(255,255,255,0.7); }
      .iconbtn:hover { color: #fff; background: rgba(255,255,255,0.16); }
      .iconbtn.close:hover { color: #fff; background: rgba(248,81,73,0.4); }
      .compact-flag {
        position: absolute;
        top: 50%;
        left: 12px;
        transform: translateY(-50%);
        height: 15px;
        border-radius: 2px;
        box-shadow: 0 0 0 1px rgba(255, 255, 255, 0.25);
      }
      .rows { padding-left: 24px; }
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
      .checking { font-size: 11.5px; color: rgba(255,255,255,0.75); padding-left: 24px; }
    </style>
    <div class="panel">
      <div class="content" id="drag-handle"${tooltipAttr}>
        <div class="button-stack">
          <button class="iconbtn" id="expand-btn" title="Expand" aria-label="Expand">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M15 3h6v6"/><path d="M9 21H3v-6"/><path d="M21 3l-7 7"/><path d="M3 21l7-7"/></svg>
          </button>
          <button class="iconbtn close" id="close-btn" title="Turn off floating view" aria-label="Turn off floating view">✕</button>
        </div>
        ${r && r.geoCountryFlag ? `<img class="compact-flag" src="${escapeHtml(r.geoCountryFlag)}" alt="" />` : ''}
        ${
          r
            ? `<div class="rows">${row('ORG', escapeHtml(r.org || '—'))}${row('ISSUER', escapeHtml(r.issuerOrg || '—'))}</div>`
            : `<div class="checking">Checking ${escapeHtml(currentHostname)}…</div>`
        }
      </div>
    </div>
  `;

  shadow.getElementById('expand-btn').addEventListener('click', () => setCompact(false));
  shadow.getElementById('close-btn').addEventListener('click', turnOff);

  attachDrag(host, shadow.getElementById('drag-handle'), pos);
}

function renderFull(host, shadow, pos) {
  const r = currentResult;
  const status = r ? overallStatus(r.issues) : '';

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
      .label { flex: none; width: 74px; color: #8b949e; font-size: 10px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; }
      .value { flex: 1; min-width: 0; overflow-wrap: break-word; font-size: 12px; font-family: ui-monospace, "SF Mono", Consolas, monospace; }
      .value a { color: #58a6ff; }
      .value a:hover { text-decoration: none; }
      .flag { width: auto; height: 14px; vertical-align: -3px; margin-right: 6px; }
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
          <div class="verdict ${status}">${r ? escapeHtml(verdictText(r, status)) : 'Checking…'}</div>
        </div>
        <button class="iconbtn" id="compact-btn" title="Compact view" aria-label="Compact view">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 14h6v6"/><path d="M20 10h-6V4"/><path d="M14 10l7-7"/><path d="M3 21l7-7"/></svg>
        </button>
        <button class="iconbtn close" id="close-btn" title="Turn off floating view" aria-label="Turn off floating view">✕</button>
      </div>
      <div class="body">
      ${
        !r
          ? `<div class="checking">Waiting for the certificate check to finish…</div>`
          : `
      ${
        r.org || r.protocol
          ? `<div class="rows">${row('Organization', escapeHtml(r.org || '—'))}${row('Issuer', escapeHtml(r.issuerOrg || '—'))}</div>`
          : ''
      }
      <div id="issues">${(r.issues || [])
        .map((i) => {
          const info = ISSUE_LABELS[i] || { label: i, level: 'warning' };
          return `<div class="issue ${info.level}">${escapeHtml(info.label)}</div>`;
        })
        .join('')}</div>
      ${
        r.protocol || r.chainLength
          ? `<details>
              <summary>SSL</summary>
              <div class="rows">
                ${row('Protocol', escapeHtml(`${r.protocol || '—'} ${r.cipherSuite || ''}`.trim()))}
                ${row('Created', fmtCreated(r.notBefore))}
                ${row('Expires', fmtExpires(r.notAfter))}
                ${row('Chain', escapeHtml(fmtChain(r)))}
                ${row('OCSP Stapled', r.ocspStapled ? 'Yes' : 'No')}
                ${r.handshakeMs ? row('Handshake', `${r.handshakeMs} ms`) : ''}
                ${r.dnsNames && r.dnsNames.length ? row('Covers', escapeHtml(r.dnsNames.join(', '))) : ''}
              </div>
            </details>`
          : ''
      }
      ${
        r.protocol || r.chainLength || r.geoCountry || r.geoAsn || r.geoAsName
          ? `<details>
              <summary>Hosting</summary>
              <div class="rows">
                ${r.protocol || r.chainLength ? row('Server', escapeHtml(r.server || 'Not disclosed')) : ''}
                ${r.poweredBy ? row('Powered By', escapeHtml(r.poweredBy)) : ''}
                ${r.protocol || r.chainLength ? row('HTTP/2', r.http2 ? 'Yes' : 'No') : ''}
                ${locationRow(r)}
                ${networkRow(r)}
              </div>
            </details>`
          : ''
      }
      ${
        r.registrarName || r.domainCreated
          ? `<details>
              <summary>Domain</summary>
              <div class="rows">
                ${r.registrarName ? row('Registrar', escapeHtml(r.registrarName)) : ''}
                ${r.domainCreated ? row('Created', fmtCreated(r.domainCreated)) : ''}
                ${r.domainExpires ? row('Expires', fmtExpires(r.domainExpires)) : ''}
                ${r.dnsProviders && r.dnsProviders.length ? row('DNS Provider', escapeHtml(r.dnsProviders.join(', '))) : ''}
                ${r.ownerOrg ? row('Owner', escapeHtml(r.ownerOrg)) : ''}
              </div>
            </details>`
          : ''
      }`
      }
      </div>
    </div>
  `;

  shadow.getElementById('compact-btn').addEventListener('click', () => setCompact(true));
  shadow.getElementById('close-btn').addEventListener('click', turnOff);

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
  chrome.storage.local.get(['floatViewEnabled', 'floatViewCompact']).then((stored) => {
    floatViewEnabled = !!stored.floatViewEnabled;
    compactMode = !!stored.floatViewCompact;
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
