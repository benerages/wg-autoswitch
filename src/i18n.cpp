// i18n.cpp - Sprachwahl und Uebersetzung (siehe i18n.h).
#include "common.h"
#include "i18n.h"
#include "i18n_table.h"

namespace wgas {

namespace {
Lang g_lang = Lang::En;
constexpr wchar_t kUserKey[] = L"Software\\WgAutoSwitch";
wchar_t g_override[4];
}

void InitLanguage(bool system) {
    if (!system) {
        const wchar_t* o = LanguageOverride();
        if (o) { g_lang = StrIEq(o, L"de") ? Lang::De : Lang::En; return; }
    }
    const LANGID id = system ? GetSystemDefaultUILanguage() : GetUserDefaultUILanguage();
    g_lang = PRIMARYLANGID(id) == LANG_GERMAN ? Lang::De : Lang::En;
}

Lang CurrentLanguage() { return g_lang; }

const wchar_t* LanguageOverride() {
    DWORD cb = sizeof g_override;
    if (RegGetValueW(HKEY_CURRENT_USER, kUserKey, L"Language", RRF_RT_REG_SZ, nullptr, g_override, &cb) != ERROR_SUCCESS)
        return nullptr;
    return (StrIEq(g_override, L"de") || StrIEq(g_override, L"en")) ? g_override : nullptr;
}

bool SetLanguageOverride(const wchar_t* code) {
    HKEY k;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, kUserKey, 0, nullptr, 0, KEY_SET_VALUE, nullptr, &k, nullptr) != ERROR_SUCCESS)
        return false;
    bool ok;
    if (code) ok = RegSetValueExW(k, L"Language", 0, REG_SZ, reinterpret_cast<const BYTE*>(code),
                                  static_cast<DWORD>((wcslen(code) + 1) * sizeof(wchar_t))) == ERROR_SUCCESS;
    else {
        const LSTATUS rc = RegDeleteValueW(k, L"Language");
        ok = rc == ERROR_SUCCESS || rc == ERROR_FILE_NOT_FOUND;
    }
    RegCloseKey(k);
    return ok;
}

// Lineare Suche: ~260 Eintraege, aufgerufen nur bei Ereignissen und Anzeige - kein Hotpath.
const wchar_t* T(const wchar_t* key) {
    for (const TrEntry& e : kTrTable) {
        if (StrEq(e.key, key)) {
            if (g_lang == Lang::En) return e.en;
            return e.de ? e.de : e.key;
        }
    }
    return key;
}

} // namespace wgas
