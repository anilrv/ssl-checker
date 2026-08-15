// The list of languages the popup's switcher offers. Chrome extensions can't enumerate
// their own bundled _locales/* folders at runtime, so this has to be maintained by hand and
// kept in sync with which _locales/<code>/messages.json files actually exist. `code` must be
// a valid Chrome extension locale code (https://developer.chrome.com/docs/extensions/reference/i18n/#supported-locales).
//
// `name` is the language's own autonym (what it calls itself), not a translation — every
// language picker in the world shows "Deutsch"/"日本語" even when the surrounding UI is in
// English, so these are never run through t().  'auto' is the one exception: it isn't a
// language, so its label comes from the 'language_auto' message key instead.
export const SUPPORTED_LANGUAGES = [
  { code: 'auto', name: null },
  { code: 'en', name: 'English' },
  { code: 'de', name: 'Deutsch' },
  { code: 'fr', name: 'Français' },
  { code: 'pt_BR', name: 'Português (Brasil)' },
  { code: 'zh_CN', name: '简体中文' },
  { code: 'tr', name: 'Türkçe' },
  { code: 'ja', name: '日本語' },
  { code: 'ru', name: 'Русский' },
];
