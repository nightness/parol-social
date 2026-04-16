// ParolNet PWA — Internationalization
// JSON lang files loaded at boot, cached by SW.

const SUPPORTED_LANGS = [
    'en', 'ru', 'fa', 'zh-CN', 'zh-TW', 'ko', 'ja',
    'fr', 'de', 'it', 'pt', 'ar', 'es', 'tr', 'my', 'vi'
];

const RTL_LANGS = ['ar', 'fa'];

let strings = {};
let currentLang = 'en';

export async function initI18n(savedLang) {
    currentLang = savedLang || detectLanguage();
    await loadStrings(currentLang);
    applyToDOM();
}

async function loadStrings(lang) {
    try {
        const resp = await fetch('./lang/' + lang + '.json');
        if (!resp.ok) throw new Error(resp.status);
        strings = await resp.json();
    } catch {
        if (lang !== 'en') {
            const resp = await fetch('./lang/en.json');
            strings = await resp.json();
            currentLang = 'en';
        }
    }
}

export function t(key, params) {
    let str = strings[key] || key;
    if (params) {
        for (const [k, v] of Object.entries(params)) {
            str = str.replaceAll('{' + k + '}', v);
        }
    }
    return str;
}

export function getCurrentLang() {
    return currentLang;
}

export async function changeLanguage(lang) {
    if (!SUPPORTED_LANGS.includes(lang)) return;
    currentLang = lang;
    await loadStrings(lang);
    applyToDOM();
}

function detectLanguage() {
    const nav = navigator.language || navigator.userLanguage || 'en';
    // Exact match first
    if (SUPPORTED_LANGS.includes(nav)) return nav;
    // Try base language (e.g. 'zh-CN' from 'zh-Hans-CN')
    const base = nav.split('-')[0];
    // Special handling for Chinese
    if (base === 'zh') {
        if (nav.includes('TW') || nav.includes('Hant')) return 'zh-TW';
        return 'zh-CN';
    }
    if (SUPPORTED_LANGS.includes(base)) return base;
    return 'en';
}

export function applyToDOM() {
    const isRtl = RTL_LANGS.includes(currentLang);
    document.documentElement.lang = currentLang;
    document.documentElement.dir = isRtl ? 'rtl' : 'ltr';

    document.querySelectorAll('[data-i18n]').forEach(el => {
        const key = el.getAttribute('data-i18n');
        el.textContent = t(key);
    });
    document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
        el.placeholder = t(el.getAttribute('data-i18n-placeholder'));
    });
    document.querySelectorAll('[data-i18n-title]').forEach(el => {
        el.title = t(el.getAttribute('data-i18n-title'));
    });
    document.querySelectorAll('[data-i18n-html]').forEach(el => {
        el.innerHTML = t(el.getAttribute('data-i18n-html'));
    });
}

export { SUPPORTED_LANGS };
