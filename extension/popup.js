import { getFunctionUrl, fetchFunctionKey, ensureFunctionKey, buildCheckUrl } from './lib/config.js';

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

const sealEl = document.getElementById('seal');
const sealGlyphEl = document.getElementById('seal-glyph');
const verdictEl = document.getElementById('verdict');
const rescanBtn = document.getElementById('rescan');
const floatViewBtn = document.getElementById('float-view');

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
  const trust = result.chainVerified ? 'trusted' : result.chainComplete ? 'untrusted root' : 'incomplete';
  return `${result.chainLength} cert${result.chainLength > 1 ? 's' : ''} · ${trust}`;
}

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
  if (status === 'info') return result.error || 'Could not fully check this site';
  if (!result.issues || result.issues.length === 0) return 'No issues found';
  return `${result.issues.length} issue${result.issues.length > 1 ? 's' : ''} found`;
}

function row(label, value, extraClass) {
  return `<div class="row"><span class="label">${escapeHtml(label)}</span><span class="value${extraClass ? ' ' + extraClass : ''}">${value}</span></div>`;
}

function networkRow(result) {
  if (!result.geoAsName && !result.geoAsn) return '';
  const asnNum = (result.geoAsn || '').replace(/^AS/i, '');
  const asnLink = asnNum
    ? `<a href="https://radar.cloudflare.com/asn/${encodeURIComponent(asnNum)}" target="_blank" rel="noopener noreferrer">${escapeHtml(result.geoAsn)}</a>`
    : escapeHtml(result.geoAsn || '');
  const name = result.geoAsName ? escapeHtml(result.geoAsName) : '';
  const value = name && asnNum ? `${name} (${asnLink})` : name || asnLink;
  return row('Network', value, 'mono');
}

function locationRow(result) {
  if (!result.geoCountry) return '';
  const place = result.geoCity ? `${result.geoCity}, ${result.geoCountry}` : result.geoCountry;
  const flag = result.geoCountryFlag
    ? `<img class="flag" src="${escapeHtml(result.geoCountryFlag)}" alt="" />`
    : '';
  return row('Location', `${flag}${escapeHtml(place)}`, 'mono');
}

function render(tab, result) {
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
    verdictEl.textContent = 'No scan data yet for this tab.';
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

  const status = overallStatus(result.issues);
  sealEl.dataset.status = status;
  sealGlyphEl.textContent = sealGlyph(status);
  sealEl.classList.remove('stamp');
  void sealEl.offsetWidth; // restart animation
  sealEl.classList.add('stamp');

  verdictEl.className = status;
  verdictEl.textContent = verdictText(result, status);

  if (result.org || result.protocol) {
    identityEl.innerHTML =
      row('Organization', escapeHtml(result.org || '—'), 'mono') +
      row('Issuer', escapeHtml(result.issuerOrg || '—'), 'mono');
  } else {
    identityEl.innerHTML = '';
  }

  const issues = result.issues || [];
  issuesEl.innerHTML = issues
    .map((i) => {
      const info = ISSUE_LABELS[i] || { label: i, level: 'warning' };
      return `<div class="issue ${info.level}">${escapeHtml(info.label)}</div>`;
    })
    .join('');

  const hasProbe = result.protocol || result.chainLength;

  if (hasProbe) {
    techEl.style.display = '';
    techRowsEl.innerHTML =
      row('Protocol', escapeHtml(`${result.protocol || '—'} ${result.cipherSuite || ''}`.trim()), 'mono') +
      row('Created', fmtCreated(result.notBefore), 'mono') +
      row('Expires', fmtExpires(result.notAfter), 'mono') +
      row('Chain', escapeHtml(fmtChain(result)), 'mono') +
      row('OCSP Stapled', result.ocspStapled ? 'Yes' : 'No', 'mono') +
      (result.handshakeMs ? row('Handshake', `${result.handshakeMs} ms`, 'mono') : '') +
      (result.dnsNames && result.dnsNames.length
        ? row('Covers', escapeHtml(result.dnsNames.join(', ')), 'mono')
        : '');
  } else {
    techEl.style.display = 'none';
    techRowsEl.innerHTML = '';
  }

  const hasHosting = hasProbe || result.geoCountry || result.geoAsn || result.geoAsName;
  if (hasHosting) {
    hostingEl.style.display = '';
    hostingRowsEl.innerHTML =
      (hasProbe ? row('Server', escapeHtml(result.server || 'Not disclosed'), 'mono') : '') +
      (result.poweredBy ? row('Powered By', escapeHtml(result.poweredBy), 'mono') : '') +
      (hasProbe ? row('HTTP/2', result.http2 ? 'Yes' : 'No', 'mono') : '') +
      locationRow(result) +
      networkRow(result);
  } else {
    hostingEl.style.display = 'none';
    hostingRowsEl.innerHTML = '';
  }

  if (result.registrarName || result.domainCreated) {
    domainEl.style.display = '';
    domainRowsEl.innerHTML =
      (result.registrarName ? row('Registrar', escapeHtml(result.registrarName), 'mono') : '') +
      (result.domainCreated ? row('Created', fmtCreated(result.domainCreated), 'mono') : '') +
      (result.domainExpires ? row('Expires', fmtExpires(result.domainExpires), 'mono') : '') +
      (result.dnsProviders && result.dnsProviders.length
        ? row('DNS Provider', escapeHtml(result.dnsProviders.join(', ')), 'mono')
        : '') +
      (result.ownerOrg ? row('Owner', escapeHtml(result.ownerOrg), 'mono') : '');
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
    render(tab, { issues: [], error: 'Could not reach the checking service: ' + e.message });
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
      render(tab, { issues: [], error: 'Function key was rejected by the backend.' });
      return;
    }
    const result = await resp.json();
    render(tab, result);
  } catch (e) {
    render(tab, { issues: [], error: 'Could not reach the checking service: ' + e.message });
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
  floatViewBtn.title = enabled ? 'Turn off floating view' : 'Show floating view on page';
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
