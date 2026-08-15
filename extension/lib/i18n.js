// chrome.i18n.getMessage() is locked to the browser's own UI language — there's no API to
// override it at runtime. To let the user pick a language inside the extension itself, this
// module keeps an in-memory override: a parsed messages.json for the chosen locale, fetched
// once by setLanguage() (called from the popup's language switcher) and cached in
// chrome.storage.local as 'uiMessagesOverride' so every surface (this popup on next open,
// background.js, content.js) can read it back without re-fetching. t() checks this override
// before falling back to the real chrome.i18n API, which is what runs when the user has
// never picked a language (or picked "auto") — ordinary browser-language behavior.

let overrideMessages = null;

// Must be awaited once, before the first t() call, by every surface that imports this
// module (see the top of popup.js) — seeds the in-memory override from whatever was last
// stored. Safe to call more than once or from multiple importers; only the first call does
// any work, the rest just await the same cached promise.
let loadPromise = null;
export function loadStoredOverride() {
  if (!loadPromise) {
    loadPromise = chrome.storage.local.get('uiMessagesOverride').then(({ uiMessagesOverride }) => {
      overrideMessages = uiMessagesOverride || null;
    });
  }
  return loadPromise;
}

// Keeps every importer's in-memory copy in sync the moment the popup calls setLanguage()
// (including a different popup instance, or background.js, or content.js's own duplicate of
// this logic), without needing to re-read storage on every t() call.
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'local' && changes.uiMessagesOverride) {
    overrideMessages = changes.uiMessagesOverride.newValue || null;
  }
});

// Called by the popup's language dropdown. code === 'auto' (or falsy) reverts to the
// browser's own UI language — ordinary chrome.i18n behavior. Updates the in-memory override
// immediately (not just via the onChanged round-trip above) so the *calling* context sees
// the new language right away, without waiting on its own storage-change event.
export async function setLanguage(code) {
  if (!code || code === 'auto') {
    overrideMessages = null;
    await chrome.storage.local.set({ uiLanguage: 'auto', uiMessagesOverride: null });
    return;
  }
  const resp = await fetch(chrome.runtime.getURL(`_locales/${code}/messages.json`));
  const messages = await resp.json();
  overrideMessages = messages;
  await chrome.storage.local.set({ uiLanguage: code, uiMessagesOverride: messages });
}

export async function getStoredLanguage() {
  const { uiLanguage } = await chrome.storage.local.get('uiLanguage');
  return uiLanguage || 'auto';
}

// Replicates chrome.i18n's own $NAME$ placeholder substitution against a raw messages.json
// entry: each placeholder's "content" is "$N$", a 1-indexed reference into `substitutions`.
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

// chrome.i18n.getMessage returns '' for an unknown key (never throws), so callers can gate
// on truthiness directly — this wrapper preserves that contract.
//
// Falling through to chrome.i18n.getMessage() is ONLY correct in 'auto' mode (no override —
// ordinary browser-language behavior, including chrome.i18n's own default_locale fallback).
// Once the user has explicitly picked a language, a key that override is missing must NOT
// fall through to chrome.i18n.getMessage(): that reads the *browser's* actual UI language,
// which can differ from the explicitly-chosen one and would silently leak text in the wrong
// language (e.g. picking "English" while the browser itself is German would otherwise show
// German for any key the 'en' file omits — which includes every issue_* key, by design; see
// issueInfo() in popup.js/content.js). So a missing key under an active override returns ''
// and lets the *caller's* own fallback chain (e.g. issueInfo()'s backend-label fallback)
// take over, same as it does in 'auto' mode when chrome.i18n itself has no key either.
export function t(key, substitutions) {
  if (overrideMessages) {
    const entry = overrideMessages[key];
    return entry && entry.message ? applyPlaceholders(entry.message, entry.placeholders, substitutions) : '';
  }
  return chrome.i18n.getMessage(key, substitutions) || '';
}
