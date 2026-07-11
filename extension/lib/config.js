// This deployment's backend URL is fixed and public — there's nothing for the user to
// configure. The function key isn't typed in either: the extension fetches it itself from
// the backend's /api/bootstrap endpoint, which is gated server-side by Origin + rate limit
// rather than by a key of its own.

const FUNCTION_URL = 'https://ssl-checker.anilrv.in/api/checkssl';
const BOOTSTRAP_URL = 'https://ssl-checker.anilrv.in/api/bootstrap';

export function getFunctionUrl() {
  return FUNCTION_URL;
}

export async function getFunctionKey() {
  const { functionKey } = await chrome.storage.local.get('functionKey');
  return functionKey || null;
}

export async function setFunctionKey(key) {
  await chrome.storage.local.set({ functionKey: key });
}

export async function fetchFunctionKey() {
  const resp = await fetch(BOOTSTRAP_URL);
  if (!resp.ok) throw new Error(`bootstrap failed: ${resp.status}`);
  const { key } = await resp.json();
  if (!key) throw new Error('bootstrap returned no key');
  await setFunctionKey(key);
  return key;
}

export async function ensureFunctionKey() {
  const existing = await getFunctionKey();
  if (existing) return existing;
  return fetchFunctionKey();
}

export function buildCheckUrl(functionUrl, hostname, { force = false, key = null } = {}) {
  const url = new URL(functionUrl);
  url.searchParams.set('host', hostname);
  if (force) url.searchParams.set('force', '1');
  if (key) url.searchParams.set('code', key);
  return url.toString();
}
