import { getFunctionUrl, fetchFunctionKey, ensureFunctionKey, buildCheckUrl } from './lib/config.js';

const DEFAULT_TITLE = 'SSL Issue Checker';

// Fallback only — the badge reads severities from the backend's issueDetails on the
// result (issueCatalog in backend/main.go is the authority), so new rules ship without
// an extension update. This map covers just the client-side 'no-https' code (no backend
// call happens for http:// tabs) and cached rows written before issueDetails existed.
// Do NOT add new backend codes here; add them to the backend catalog instead.
const ISSUE_LEVELS = {
  'no-https': 'critical',
  expired: 'critical',
  'not-yet-valid': 'critical',
  'self-signed': 'critical',
  'incomplete-chain': 'warning',
  'untrusted-chain': 'critical',
  'hostname-mismatch': 'critical',
  'weak-protocol': 'warning',
  'recently-registered': 'critical',
  'young-domain': 'warning',
  'cert-expiring-soon': 'warning',
  'domain-expiring-soon': 'warning',
  'resolve-failed': 'info',
  'probe-failed': 'info',
};

// Latest known result per tab, kept only for the life of this service worker instance —
// feeds the content script's floating panel (see content.js) so it doesn't need to
// re-request a check itself. Not persisted: worst case after a worker restart is the
// content script gets an empty response and just waits for the next natural recheck.
const latestResults = new Map();

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status !== 'complete' || !tab.url) return;
  handleTab(tabId, tab.url);
});

chrome.tabs.onActivated.addListener(({ tabId }) => {
  chrome.tabs.get(tabId, (tab) => {
    if (chrome.runtime.lastError || !tab || !tab.url) return;
    handleTab(tabId, tab.url);
  });
});

chrome.tabs.onRemoved.addListener((tabId) => {
  latestResults.delete(tabId);
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type !== 'getResult' || !sender.tab) return false;
  sendResponse(latestResults.get(sender.tab.id) || null);
  return false;
});

async function handleTab(tabId, url) {
  if (!/^https?:\/\//i.test(url)) {
    clearIndicators(tabId);
    latestResults.delete(tabId);
    return;
  }
  if (url.startsWith('http://')) {
    updateBadge(tabId, ['no-https']);
    chrome.action.setTitle({ tabId, title: `${DEFAULT_TITLE} — no HTTPS` });
    latestResults.delete(tabId);
    return;
  }

  const functionUrl = await getFunctionUrl();
  let functionKey;
  try {
    functionKey = await ensureFunctionKey();
  } catch (e) {
    clearIndicators(tabId);
    return;
  }

  let hostname;
  try {
    hostname = new URL(url).hostname;
  } catch (e) {
    return;
  }

  try {
    let resp = await fetch(buildCheckUrl(functionUrl, hostname, { key: functionKey }));
    if (resp.status === 401 || resp.status === 403) {
      try {
        functionKey = await fetchFunctionKey();
        resp = await fetch(buildCheckUrl(functionUrl, hostname, { key: functionKey }));
      } catch (e) {
        // bootstrap unreachable — fall through to the stale response below
      }
    }
    if (!resp.ok) {
      clearIndicators(tabId);
      return;
    }
    const result = await resp.json();
    updateBadge(tabId, result.issues || [], result);
    updateTooltip(tabId, result);
    latestResults.set(tabId, { hostname, result });
    chrome.tabs.sendMessage(tabId, { type: 'sslResult', hostname, result }).catch(() => {
      // content script may not be attached (e.g. this frame isn't https, or it hasn't
      // loaded yet) — it'll pick up the cached result via getResult once it does
    });
  } catch (e) {
    clearIndicators(tabId);
  }
}

function clearIndicators(tabId) {
  chrome.action.setBadgeText({ tabId, text: '' });
  chrome.action.setTitle({ tabId, title: DEFAULT_TITLE });
}

// Severity for one issue code: backend-supplied issueDetails wins, local map is the
// fallback (see the ISSUE_LEVELS comment). result may be undefined for client-side
// codes like 'no-https'.
function levelOf(result, code) {
  const fromBackend = ((result && result.issueDetails) || []).find((d) => d.code === code);
  return (fromBackend && fromBackend.level) || ISSUE_LEVELS[code] || 'warning';
}

function updateBadge(tabId, issues, result) {
  const levels = issues.map((i) => levelOf(result, i));

  if (issues.length === 0) {
    chrome.action.setBadgeText({ tabId, text: 'OK' });
    chrome.action.setBadgeBackgroundColor({ tabId, color: '#2e7d32' });
  } else if (levels.every((l) => l === 'info')) {
    chrome.action.setBadgeText({ tabId, text: '?' });
    chrome.action.setBadgeBackgroundColor({ tabId, color: '#9e9e9e' });
  } else {
    chrome.action.setBadgeText({ tabId, text: String(issues.length) });
    chrome.action.setBadgeBackgroundColor({ tabId, color: levels.includes('critical') ? '#c62828' : '#f9a825' });
  }
}

function updateTooltip(tabId, result) {
  const title = result.issuerOrg ? `SSL: ${result.issuerOrg}` : DEFAULT_TITLE;
  chrome.action.setTitle({ tabId, title });
}
