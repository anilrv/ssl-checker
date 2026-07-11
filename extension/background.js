import { getFunctionUrl, fetchFunctionKey, ensureFunctionKey, buildCheckUrl } from './lib/config.js';

const DEFAULT_TITLE = 'SSL Issue Checker';

// Severity per issue — must stay in sync with ISSUE_LABELS in popup.js/content.js so the
// badge color always agrees with the severity the popup and floating panel display.
const ISSUE_LEVELS = {
  'no-https': 'critical',
  expired: 'critical',
  'not-yet-valid': 'critical',
  'self-signed': 'critical',
  'incomplete-chain': 'warning',
  'untrusted-chain': 'critical',
  'hostname-mismatch': 'critical',
  'weak-protocol': 'warning',
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
    updateBadge(tabId, result.issues || []);
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

function updateBadge(tabId, issues) {
  const levels = issues.map((i) => ISSUE_LEVELS[i] || 'warning');

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
