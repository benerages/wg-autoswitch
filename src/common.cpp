// common.cpp - gemeinsamer Code von wgas.exe und wgas-gui.exe (siehe common.h).
#include "common.h"
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>
#include <bcrypt.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "version.lib")
#pragma comment(lib, "wlanapi.lib")
#pragma comment(lib, "advapi32.lib")

namespace wgas {

Paths g_paths;

namespace {
constexpr wchar_t kTrustedInstallerSid[] =
    L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
}

// =====================================================================================
// Pfade und Text
// =====================================================================================

bool InitPaths(Paths& p) {
    wchar_t pf[MAX_PATH], pd[MAX_PATH];
    const DWORD a = ExpandEnvironmentStringsW(L"%ProgramFiles%", pf, MAX_PATH);
    const DWORD b = ExpandEnvironmentStringsW(L"%ProgramData%", pd, MAX_PATH);
    if (!a || a > MAX_PATH || !b || b > MAX_PATH || pf[0] == L'%' || pd[0] == L'%') return false;
    swprintf_s(p.progDir, MAX_PATH, L"%ls\\WgAutoSwitch", pf);
    swprintf_s(p.exe,     MAX_PATH, L"%ls\\WgAutoSwitch\\wgas.exe", pf);
    swprintf_s(p.guiExe,  MAX_PATH, L"%ls\\WgAutoSwitch\\wgas-gui.exe", pf);
    swprintf_s(p.dataDir, MAX_PATH, L"%ls\\WgAutoSwitch", pd);
    swprintf_s(p.cfg,     MAX_PATH, L"%ls\\WgAutoSwitch\\config.ini", pd);
    swprintf_s(p.tunDir,  MAX_PATH, L"%ls\\WgAutoSwitch\\tunnels", pd);
    // Das WireGuard-MSI installiert fest nach %ProgramFiles%\WireGuard (kein waehlbarer Ordner);
    // %ProgramFiles% zeigt auch dann richtig, wenn Windows nicht auf C: liegt.
    swprintf_s(p.wgExe,   MAX_PATH, L"%ls\\WireGuard\\wireguard.exe", pf);
    return true;
}

void Appendf(wchar_t* buf, size_t cap, const wchar_t* fmt, ...) {
    const size_t used = wcslen(buf);
    if (used + 1 >= cap) return;
    va_list ap;
    va_start(ap, fmt);
    _vsnwprintf_s(buf + used, cap - used, _TRUNCATE, fmt, ap);
    va_end(ap);
}

void MacToStr(const unsigned char* m, wchar_t* out, size_t cap) {
    swprintf_s(out, cap, L"%02x:%02x:%02x:%02x:%02x:%02x",
               static_cast<unsigned>(m[0]), static_cast<unsigned>(m[1]), static_cast<unsigned>(m[2]),
               static_cast<unsigned>(m[3]), static_cast<unsigned>(m[4]), static_cast<unsigned>(m[5]));
}

void SanitizeField(const wchar_t* in, wchar_t* out, size_t cap) {
    size_t i = 0;
    for (; in[i] && i + 1 < cap; ++i) out[i] = (in[i] < 0x20 || in[i] == 0x7F) ? L'?' : in[i];
    out[i] = 0;
}

wchar_t* NextField(wchar_t*& p) {
    wchar_t* start = p;
    while (*p && *p != L'\t') ++p;
    if (*p) *p++ = 0;
    return start;
}

const wchar_t* KindName(IfKind k) {
    switch (k) {
    case IfKind::Ethernet: return T(L"LAN");
    case IfKind::Wifi:     return T(L"WLAN");
    case IfKind::Mobile:   return T(L"Mobilfunk");
    default:               return T(L"Andere");
    }
}

const wchar_t* KindKey(IfKind k) {
    switch (k) {
    case IfKind::Ethernet: return L"ethernet";
    case IfKind::Wifi:     return L"wifi";
    case IfKind::Mobile:   return L"mobile";
    default:               return L"other";
    }
}

const wchar_t* ConnName(Connectivity c) {
    switch (c) {
    case Connectivity::None:        return T(L"keine");
    case Connectivity::Local:       return T(L"nur lokal");
    case Connectivity::Constrained: return T(L"eingeschraenkt (Captive Portal)");
    case Connectivity::Internet:    return L"Internet";
    default:                        return T(L"unbekannt");
    }
}

bool ParseKind(const wchar_t* s, IfKind& k) {
    if (StrIEq(s, L"ethernet") || StrIEq(s, L"lan"))     { k = IfKind::Ethernet; return true; }
    if (StrIEq(s, L"wifi") || StrIEq(s, L"wlan"))        { k = IfKind::Wifi;     return true; }
    if (StrIEq(s, L"mobile") || StrIEq(s, L"mobilfunk")) { k = IfKind::Mobile;   return true; }
    if (StrIEq(s, L"other"))                             { k = IfKind::Other;    return true; }
    return false;
}

const wchar_t* TunnelLabel(const Config& c, int idx) {
    return (idx >= 0 && idx < c.tunnelCount) ? c.tunnels[idx] : T(L"kein Tunnel");
}

bool FileExists(const wchar_t* path) {
    const DWORD a = GetFileAttributesW(path);
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

ULONGLONG NowFileTime() {
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    return (static_cast<ULONGLONG>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
}

void FormatLocalTime(ULONGLONG t, wchar_t* out, size_t cap) {
    FILETIME ft;
    ft.dwLowDateTime  = static_cast<DWORD>(t & 0xFFFFFFFFull);
    ft.dwHighDateTime = static_cast<DWORD>(t >> 32);
    SYSTEMTIME utc, loc;
    if (FileTimeToSystemTime(&ft, &utc) && SystemTimeToTzSpecificLocalTime(nullptr, &utc, &loc))
        swprintf_s(out, cap, L"%02d:%02d", static_cast<int>(loc.wHour), static_cast<int>(loc.wMinute));
    else
        swprintf_s(out, cap, L"?");
}

void FormatBytes(ULONG64 v, wchar_t* out, size_t cap) {
    if (v < 1024ull)                    swprintf_s(out, cap, L"%llu B", v);
    else if (v < 1024ull * 1024)        swprintf_s(out, cap, L"%.1f KB", static_cast<double>(v) / 1024.0);
    else if (v < 1024ull * 1024 * 1024) swprintf_s(out, cap, L"%.1f MB", static_cast<double>(v) / (1024.0 * 1024.0));
    else                                swprintf_s(out, cap, L"%.2f GB", static_cast<double>(v) / (1024.0 * 1024.0 * 1024.0));
}

// =====================================================================================
// Registry (HKLM\SOFTWARE\WgAutoSwitch): Fail-safe-Tunnel. Schreiben nur als Admin.
// =====================================================================================

bool RegWrite(const wchar_t* name, DWORD type, const void* data, DWORD bytes) {
    HKEY k;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, kRegKey, 0, nullptr, 0, KEY_SET_VALUE, nullptr, &k, nullptr) != ERROR_SUCCESS)
        return false;
    const bool ok = RegSetValueExW(k, name, 0, type, static_cast<const BYTE*>(data), bytes) == ERROR_SUCCESS;
    RegCloseKey(k);
    return ok;
}

bool RegReadFailsafe(wchar_t* out, DWORD cap) {
    DWORD cb = cap * sizeof(wchar_t);
    if (RegGetValueW(HKEY_LOCAL_MACHINE, kRegKey, L"FailsafeTunnel", RRF_RT_REG_SZ, nullptr, out, &cb) != ERROR_SUCCESS)
        return false;
    return IsValidTunnelName(out);
}

void RegWriteFailsafe(const wchar_t* name) {
    RegWrite(L"FailsafeTunnel", REG_SZ, name, static_cast<DWORD>((wcslen(name) + 1) * sizeof(wchar_t)));
}

// =====================================================================================
// Konfiguration
// =====================================================================================

namespace {

// Kommentar am Zeilenende (" ; ..." / " # ...") und Leerraum entfernen.
// "..." schuetzt Werte mit ; oder # (z. B. SSIDs) und fuehrende/abschliessende Leerzeichen.
void CleanValue(wchar_t* v) {
    wchar_t* s = v;
    while (*s == L' ' || *s == L'\t') ++s;
    if (*s == L'"') {
        ++s;
        wchar_t* e = s;
        while (*e && *e != L'"') ++e;
        *e = 0;
    } else {
        for (wchar_t* p = s; *p; ++p) {
            if ((*p == L';' || *p == L'#') && (p == s || p[-1] == L' ' || p[-1] == L'\t')) { *p = 0; break; }
        }
        size_t n = wcslen(s);
        while (n && (s[n - 1] == L' ' || s[n - 1] == L'\t')) s[--n] = 0;
    }
    if (s != v) memmove(v, s, (wcslen(s) + 1) * sizeof(wchar_t));
}

// Ganze Sektion roh lesen ("key=value\0key=value\0\0"). GetPrivateProfileSection liefert
// die Werte unveraendert (inkl. Anfuehrungszeichen), anders als GetPrivateProfileString.
wchar_t g_sec[16384];

bool LoadSection(const wchar_t* path, const wchar_t* sec, wchar_t* err, size_t errCap) {
    const DWORD n = GetPrivateProfileSectionW(sec, g_sec, static_cast<DWORD>(_countof(g_sec)), path);
    if (n >= _countof(g_sec) - 2) {
        swprintf_s(err, errCap, T(L"Sektion [%ls] ist zu gross."), sec);
        return false;
    }
    if (n == 0) g_sec[0] = g_sec[1] = 0;
    return true;
}

// Zerlegt eine Zeile in Schluessel und Rohwert. false bei Kommentar/Leerzeile.
bool SplitLine(const wchar_t* line, wchar_t* key, int keyCap, const wchar_t*& value) {
    const wchar_t* q = line;
    while (*q == L' ' || *q == L'\t') ++q;
    if (*q == L';' || *q == L'#' || *q == 0) return false;
    int k = 0;
    while (*q && *q != L'=' && k < keyCap - 1) key[k++] = *q++;
    while (k && (key[k - 1] == L' ' || key[k - 1] == L'\t')) --k;
    key[k] = 0;
    value = (*q == L'=') ? q + 1 : q;
    return true;
}

bool CheckKeys(const wchar_t* sec, const wchar_t* const* allowed, int nAllowed, wchar_t* err, size_t errCap) {
    for (const wchar_t* p = g_sec; *p; p += wcslen(p) + 1) {
        wchar_t key[64];
        const wchar_t* value = nullptr;
        if (!SplitLine(p, key, 64, value)) continue;
        bool known = false;
        for (int i = 0; i < nAllowed; ++i) if (StrIEq(key, allowed[i])) known = true;
        if (!known) {
            swprintf_s(err, errCap, T(L"Unbekannter Schluessel \"%ls\" in [%ls]."), key, sec);
            return false;
        }
    }
    return true;
}

// 0 = fehlt, 1 = gelesen, -1 = zu lang. Liest aus der zuletzt geladenen Sektion.
int ReadKey(const wchar_t* key, wchar_t* out, int cap) {
    for (const wchar_t* p = g_sec; *p; p += wcslen(p) + 1) {
        wchar_t k[64];
        const wchar_t* value = nullptr;
        if (!SplitLine(p, k, 64, value) || !StrIEq(k, key)) continue;
        wchar_t raw[512];
        if (StrLen(value) >= 511) { out[0] = 0; return -1; }
        StrCopy(raw, 512, value);
        CleanValue(raw);
        if (StrLen(raw) >= cap) { out[0] = 0; return -1; }
        StrCopy(out, cap, raw);
        return 1;
    }
    out[0] = 0;
    return 0;
}

} // namespace

int AddTunnel(Config& c, const wchar_t* name) {
    for (int i = 0; i < c.tunnelCount; ++i)
        if (StrIEq(c.tunnels[i], name)) return i;
    if (c.tunnelCount >= kMaxTunnels) return -2;
    StrCopy(c.tunnels[c.tunnelCount], kNameLen, name);
    return c.tunnelCount++;
}

bool LoadConfig(const wchar_t* path, Config& c, wchar_t* err, size_t errCap) {
    ResetConfig(c);
    err[0] = 0;

    // Lesbarkeit pruefen: die Profile-API meldet fehlenden Zugriff nicht.
    HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) {
        const DWORD e = GetLastError();
        if (e == ERROR_ACCESS_DENIED) swprintf_s(err, errCap, T(L"Kein Lesezugriff auf %ls (als Administrator ausfuehren)."), path);
        else swprintf_s(err, errCap, T(L"%ls nicht gefunden (Fehler %lu)."), path, e);
        return false;
    }
    CloseHandle(f);

    static const wchar_t* const kGeneralKeys[] = { L"default_tunnel", L"debounce_ms", L"no_network", L"captive_portal" };
    static const wchar_t* const kRuleKeys[] = { L"type", L"ssid", L"bssid", L"gateway_mac", L"dns_suffix", L"tunnel" };

    if (!LoadSection(path, L"general", err, errCap) || !CheckKeys(L"general", kGeneralKeys, 4, err, errCap)) return false;
    wchar_t v[kDnsLen];
    int r = ReadKey(L"default_tunnel", v, kNameLen);
    if (r != 1 || !IsValidTunnelName(v)) {
        swprintf_s(err, errCap, T(L"[general] default_tunnel fehlt oder ist ungueltig (A-Z a-z 0-9 _ = + . -, max. 32 Zeichen, nicht \"none\")."));
        return false;
    }
    c.defaultTunnel = AddTunnel(c, v);
    if ((r = ReadKey(L"debounce_ms", v, 16)) != 0) {
        unsigned ms = 0;
        if (r < 0 || !ParseUInt(v, ms) || ms < 500 || ms > 10000) {
            swprintf_s(err, errCap, T(L"[general] debounce_ms muss zwischen 500 und 10000 liegen."));
            return false;
        }
        c.debounceMs = ms;
    }
    if ((r = ReadKey(L"no_network", v, 8)) != 0) {
        if (r > 0 && StrIEq(v, L"on")) c.noNetworkOn = true;
        else if (r < 0 || !StrIEq(v, L"off")) { swprintf_s(err, errCap, T(L"[general] no_network: on oder off.")); return false; }
    }
    if ((r = ReadKey(L"captive_portal", v, 8)) != 0) {
        if (r > 0 && StrIEq(v, L"ignore")) c.captiveWait = false;
        else if (r < 0 || !StrIEq(v, L"wait")) { swprintf_s(err, errCap, T(L"[general] captive_portal: wait oder ignore.")); return false; }
    }

    static wchar_t names[8192];
    const DWORD n = GetPrivateProfileSectionNamesW(names, static_cast<DWORD>(_countof(names)), path);
    if (n >= _countof(names) - 2) { swprintf_s(err, errCap, T(L"Zu viele Sektionen.")); return false; }

    for (const wchar_t* sec = names; *sec; sec += wcslen(sec) + 1) {
        if (StrIEq(sec, L"general")) continue;
        if (!StartsWithI(sec, L"network.")) {
            swprintf_s(err, errCap, T(L"Unbekannte Sektion [%ls] (erlaubt: [general], [network.<name>])."), sec);
            return false;
        }
        const wchar_t* rname = sec + 8;
        if (!IsValidRuleName(rname)) { swprintf_s(err, errCap, T(L"Ungueltiger Regelname [%ls]."), sec); return false; }
        if (c.ruleCount >= kMaxRules) { swprintf_s(err, errCap, T(L"Mehr als %d Regeln."), kMaxRules); return false; }
        if (!LoadSection(path, sec, err, errCap) || !CheckKeys(sec, kRuleKeys, 6, err, errCap)) return false;

        Rule& rule = c.rules[c.ruleCount];
        ZeroBytes(&rule, sizeof rule);
        StrCopy(rule.name, kRuleLen, rname);
        rule.tunnel = kNoTunnel;

        if ((r = ReadKey(L"type", v, 16)) != 0) {
            if (r < 0 || !ParseKind(v, rule.kind)) { swprintf_s(err, errCap, T(L"[%ls] type: ethernet, wifi, mobile oder other."), sec); return false; }
            rule.hasKind = true;
        }
        if ((r = ReadKey(L"gateway_mac", v, 32)) != 0) {
            if (r < 0 || !ParseMac(v, rule.gwMac) || MacIsZero(rule.gwMac)) {
                swprintf_s(err, errCap, T(L"[%ls] gateway_mac: Format 00:11:22:33:44:55."), sec);
                return false;
            }
            rule.hasMac = true;
        }
        if ((r = ReadKey(L"bssid", v, 32)) != 0) {
            if (r < 0 || !ParseMac(v, rule.bssid) || MacIsZero(rule.bssid)) {
                swprintf_s(err, errCap, T(L"[%ls] bssid: Format 00:11:22:33:44:55."), sec);
                return false;
            }
            rule.hasBssid = true;
        }
        r = ReadKey(L"dns_suffix", v, kDnsLen);
        if (r < 0 || (r > 0 && v[0])) {
            if (r < 0 || !IsValidDnsSuffix(v)) { swprintf_s(err, errCap, T(L"[%ls] dns_suffix ungueltig (A-Z a-z 0-9 . -)."), sec); return false; }
            StrCopy(rule.dnsSuffix, kDnsLen, v);
            rule.hasDns = true;
        }
        r = ReadKey(L"ssid", v, kSsidLen);
        if (r < 0 || (r > 0 && v[0])) {
            const int utf8 = r > 0 ? WideCharToMultiByte(CP_UTF8, 0, v, -1, nullptr, 0, nullptr, nullptr) : 0;
            if (r < 0 || utf8 <= 1 || utf8 - 1 > 32) { swprintf_s(err, errCap, T(L"[%ls] ssid: 1-32 Byte."), sec); return false; }
            StrCopy(rule.ssid, kSsidLen, v);
            rule.hasSsid = true;
        }
        if (ReadKey(L"tunnel", v, kNameLen) != 1) {
            swprintf_s(err, errCap, T(L"[%ls] tunnel fehlt (Tunnelname oder none)."), sec);
            return false;
        }
        if (!StrIEq(v, L"none")) {
            if (!IsValidTunnelName(v)) { swprintf_s(err, errCap, T(L"[%ls] tunnel: ungueltiger Name."), sec); return false; }
            rule.tunnel = AddTunnel(c, v);
            if (rule.tunnel < 0) { swprintf_s(err, errCap, T(L"Mehr als %d Tunnel."), kMaxTunnels); return false; }
        }
        if (!RuleStrongEnough(rule)) {
            swprintf_s(err, errCap,
                       rule.tunnel == kNoTunnel
                           ? T(L"[%ls] tunnel = none braucht gateway_mac UND dns_suffix, ssid oder bssid (eine SSID allein ist faelschbar).")
                           : T(L"[%ls] braucht mindestens ein Merkmal (type, ssid, bssid, gateway_mac, dns_suffix)."),
                       sec);
            return false;
        }
        ++c.ruleCount;
    }
    return true;
}

void BuildFailsafeConfig(Config& c) {
    ResetConfig(c);
    wchar_t name[kNameLen];
    if (RegReadFailsafe(name, kNameLen)) c.defaultTunnel = AddTunnel(c, name);
}

namespace {
// Wert fuer config.ini: in "..." setzen, wenn noetig. false, wenn nicht darstellbar.
bool AppendValue(wchar_t* out, size_t cap, const wchar_t* key, const wchar_t* v) {
    bool quote = v[0] == L' ' || (v[0] && v[StrLen(v) - 1] == L' ');
    for (const wchar_t* p = v; *p; ++p) {
        if (*p == L'"' || *p < 0x20) return false;
        if (*p == L';' || *p == L'#') quote = true;
    }
    if (quote) Appendf(out, cap, L"%ls = \"%ls\"\r\n", key, v);
    else       Appendf(out, cap, L"%ls = %ls\r\n", key, v);
    return true;
}
} // namespace

bool WriteConfigText(const Config& c, wchar_t* out, size_t cap) {
    out[0] = 0;
    if (c.defaultTunnel < 0 || c.defaultTunnel >= c.tunnelCount) return false;
    Appendf(out, cap,
            L"; WG-AutoSwitch configuration (written by WG-AutoSwitch)\r\n; Features of the current network: wgas check   Apply: wgas reload\r\n\r\n[general]\r\ndefault_tunnel = %ls\r\ndebounce_ms = %u\r\nno_network = %ls\r\ncaptive_portal = %ls\r\n",
            c.tunnels[c.defaultTunnel], c.debounceMs, c.noNetworkOn ? L"on" : L"off",
            c.captiveWait ? L"wait" : L"ignore");
    for (int i = 0; i < c.ruleCount; ++i) {
        const Rule& r = c.rules[i];
        if (!IsValidRuleName(r.name)) return false;
        Appendf(out, cap, L"\r\n[network.%ls]\r\n", r.name);
        if (r.hasKind) Appendf(out, cap, L"type = %ls\r\n", KindKey(r.kind));
        if (r.hasSsid && !AppendValue(out, cap, L"ssid", r.ssid)) return false;
        wchar_t mac[24];
        if (r.hasBssid) { MacToStr(r.bssid, mac, _countof(mac)); Appendf(out, cap, L"bssid = %ls\r\n", mac); }
        if (r.hasMac)   { MacToStr(r.gwMac, mac, _countof(mac)); Appendf(out, cap, L"gateway_mac = %ls\r\n", mac); }
        if (r.hasDns) Appendf(out, cap, L"dns_suffix = %ls\r\n", r.dnsSuffix);
        Appendf(out, cap, L"tunnel = %ls\r\n", r.tunnel == kNoTunnel ? L"none" : TunnelLabel(c, r.tunnel));
    }
    return wcslen(out) + 2 < cap;   // sonst abgeschnitten
}

bool WriteUtf16File(const wchar_t* path, const wchar_t* text, bool createNew) {
    HANDLE f = CreateFileW(path, GENERIC_WRITE, 0, nullptr, createNew ? CREATE_NEW : CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return false;
    const wchar_t bom = 0xFEFF;   // UTF-16 LE: so liest die Profile-API Umlaute korrekt
    DWORD w = 0;
    const bool ok = WriteFile(f, &bom, sizeof bom, &w, nullptr) &&
                    WriteFile(f, text, static_cast<DWORD>(wcslen(text) * sizeof(wchar_t)), &w, nullptr);
    CloseHandle(f);
    return ok;
}

// =====================================================================================
// Dateirechte
// =====================================================================================

namespace {
bool IsTrustedSid(PSID sid) {
    if (IsWellKnownSid(sid, WinLocalSystemSid) || IsWellKnownSid(sid, WinBuiltinAdministratorsSid)) return true;
    PSID ti = nullptr;
    bool eq = false;
    if (ConvertStringSidToSidW(kTrustedInstallerSid, &ti)) {
        eq = EqualSid(sid, ti) != FALSE;
        LocalFree(ti);
    }
    return eq;
}
} // namespace

// Sicher = Besitzer ist SYSTEM/Administratoren/TrustedInstaller und nur diese duerfen schreiben.
bool IsSecureObject(const wchar_t* path) {
    PSID owner = nullptr;
    PACL dacl = nullptr;
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (GetNamedSecurityInfoW(path, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                              &owner, nullptr, &dacl, nullptr, &sd) != ERROR_SUCCESS)
        return false;
    bool ok = owner && dacl && IsTrustedSid(owner);
    const ACCESS_MASK kWrite = FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES |
                               FILE_DELETE_CHILD | DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_WRITE | GENERIC_ALL;
    for (DWORD i = 0; ok && i < dacl->AceCount; ++i) {
        ACE_HEADER* h = nullptr;
        if (!GetAce(dacl, i, reinterpret_cast<LPVOID*>(&h))) { ok = false; break; }
        if (h->AceFlags & INHERIT_ONLY_ACE) continue;
        if (h->AceType == ACCESS_DENIED_ACE_TYPE) continue;
        if (h->AceType != ACCESS_ALLOWED_ACE_TYPE) { ok = false; break; }
        ACCESS_ALLOWED_ACE* a = reinterpret_cast<ACCESS_ALLOWED_ACE*>(h);
        if ((a->Mask & kWrite) && !IsTrustedSid(reinterpret_cast<PSID>(&a->SidStart))) ok = false;
    }
    LocalFree(sd);
    return ok;
}

bool ConfigIsSecure(const Paths& p, wchar_t* err, size_t errCap) {
    if (!IsSecureObject(p.dataDir) || !IsSecureObject(p.cfg)) {
        swprintf_s(err, errCap, T(L"Unsichere Dateirechte auf %ls (andere als SYSTEM/Administratoren duerfen schreiben). \"wgas reload\" korrigiert das."), p.cfg);
        return false;
    }
    return true;
}

bool ApplySddl(const wchar_t* path, const wchar_t* sddl) {
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &sd, nullptr)) return false;
    BOOL present = FALSE, defaulted = FALSE;
    PACL dacl = nullptr;
    PSID owner = nullptr;
    const bool ok = GetSecurityDescriptorDacl(sd, &present, &dacl, &defaulted) &&
                    GetSecurityDescriptorOwner(sd, &owner, &defaulted) &&
                    SetNamedSecurityInfoW(const_cast<LPWSTR>(path), SE_FILE_OBJECT,
                                          OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION |
                                              PROTECTED_DACL_SECURITY_INFORMATION,
                                          owner, nullptr, dacl, nullptr) == ERROR_SUCCESS;
    LocalFree(sd);
    return ok;
}

bool GetServiceSidString(wchar_t* out, size_t cap) {
    BYTE sid[SECURITY_MAX_SID_SIZE];
    DWORD cbSid = sizeof sid;
    wchar_t dom[256];
    DWORD cchDom = static_cast<DWORD>(_countof(dom));
    SID_NAME_USE use;
    if (!LookupAccountNameW(nullptr, kSvcAccount, sid, &cbSid, dom, &cchDom, &use)) return false;
    LPWSTR s = nullptr;
    if (!ConvertSidToStringSidW(sid, &s)) return false;
    swprintf_s(out, cap, L"%ls", s);
    LocalFree(s);
    return true;
}

// Datenordner: SYSTEM + Admins Vollzugriff, Dienstkonto nur Lesen.
// Tunnelordner (private Schluessel): nur SYSTEM + Admins.
bool SecureDataDir(const Paths& p, const wchar_t* svcSid) {
    wchar_t sddl[256];
    swprintf_s(sddl, _countof(sddl), L"O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FR;;;%ls)", svcSid);
    bool ok = ApplySddl(p.dataDir, sddl);
    if (FileExists(p.cfg)) {
        swprintf_s(sddl, _countof(sddl), L"O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;%ls)", svcSid);
        ok = ApplySddl(p.cfg, sddl) && ok;
    }
    ok = ApplySddl(p.tunDir, L"O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)") && ok;
    return ok;
}

// =====================================================================================
// Netzmerkmale
// =====================================================================================

namespace {

bool IsManagedAlias(const Config& c, const wchar_t* alias) {
    for (int i = 0; i < c.tunnelCount; ++i)
        if (StrIEq(c.tunnels[i], alias)) return true;
    return false;
}

bool GatewayMac(const NET_LUID& luid, const SOCKADDR* sa, unsigned char mac[6]) {
    if (!sa || (sa->sa_family != AF_INET && sa->sa_family != AF_INET6)) return false;
    MIB_IPNET_ROW2 row;
    for (int attempt = 0; attempt < 2; ++attempt) {
        ZeroMemory(&row, sizeof row);
        row.InterfaceLuid = luid;
        if (sa->sa_family == AF_INET) row.Address.Ipv4 = *reinterpret_cast<const SOCKADDR_IN*>(sa);
        else                          row.Address.Ipv6 = *reinterpret_cast<const SOCKADDR_IN6*>(sa);
        // 1. Nachbar-Cache lesen (kein Netzverkehr), 2. nur falls leer: aktiv aufloesen (ARP/ND).
        const DWORD rc = attempt == 0 ? GetIpNetEntry2(&row) : ResolveIpNetEntry2(&row, nullptr);
        if (rc == NO_ERROR && row.PhysicalAddressLength == 6 && row.State > NlnsIncomplete &&
            !MacIsZero(row.PhysicalAddress)) {
            memcpy(mac, row.PhysicalAddress, 6);
            return true;
        }
    }
    return false;
}

// SSID und BSSID sind optional: Unter Windows 11 24H2+ kann die WLAN-API ohne
// Standortfreigabe leer bleiben.
void QueryWlan(HANDLE& wlan, const NET_LUID& luid, IfInfo& f) {
    GUID guid;
    if (ConvertInterfaceLuidToGuid(&luid, &guid) != NO_ERROR) return;
    if (!wlan) {
        DWORD ver = 0;
        if (WlanOpenHandle(2, nullptr, &ver, &wlan) != ERROR_SUCCESS) { wlan = nullptr; return; }
    }
    DWORD size = 0;
    PWLAN_CONNECTION_ATTRIBUTES ca = nullptr;
    WLAN_OPCODE_VALUE_TYPE vt;
    if (WlanQueryInterface(wlan, &guid, wlan_intf_opcode_current_connection, nullptr, &size,
                           reinterpret_cast<PVOID*>(&ca), &vt) != ERROR_SUCCESS || !ca)
        return;
    if (ca->isState == wlan_interface_state_connected) {
        const DOT11_SSID& s = ca->wlanAssociationAttributes.dot11Ssid;
        const int len = static_cast<int>(s.uSSIDLength > 32 ? 32 : s.uSSIDLength);
        const int n = len ? MultiByteToWideChar(CP_UTF8, 0, reinterpret_cast<LPCCH>(s.ucSSID), len, f.ssid, kSsidLen - 1) : 0;
        if (n > 0) { f.ssid[n] = 0; f.hasSsid = true; }
        const unsigned char* b = ca->wlanAssociationAttributes.dot11Bssid;
        if (!MacIsZero(b)) { memcpy(f.bssid, b, 6); f.hasBssid = true; }
    }
    WlanFreeMemory(ca);
}

} // namespace

bool CollectInterfaces(const Config* cfg, Snapshot& s) {
    s.ok = false;
    s.n = 0;
    const ULONG flags = GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    HANDLE heap = GetProcessHeap();
    ULONG size = 24 * 1024;
    IP_ADAPTER_ADDRESSES* buf = nullptr;
    ULONG rc = ERROR_BUFFER_OVERFLOW;
    for (int i = 0; i < 3 && rc == ERROR_BUFFER_OVERFLOW; ++i) {
        if (buf) HeapFree(heap, 0, buf);
        buf = static_cast<IP_ADAPTER_ADDRESSES*>(HeapAlloc(heap, 0, size));
        if (!buf) return false;
        rc = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, buf, &size);
    }
    if (rc == ERROR_NO_DATA) { HeapFree(heap, 0, buf); s.ok = true; return true; }
    if (rc != NO_ERROR) { HeapFree(heap, 0, buf); return false; }

    HANDLE wlan = nullptr;
    for (IP_ADAPTER_ADDRESSES* a = buf; a && s.n < kMaxIfs; a = a->Next) {
        if (a->OperStatus != IfOperStatusUp) continue;
        if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK || a->IfType == IF_TYPE_TUNNEL) continue;
        if (!a->FirstGatewayAddress) continue;
        if (a->Description && wcsstr(a->Description, L"WireGuard")) continue;     // F7
        if (cfg && a->FriendlyName && IsManagedAlias(*cfg, a->FriendlyName)) continue;

        IfInfo& f = s.ifs[s.n];
        ZeroBytes(&f, sizeof f);
        switch (a->IfType) {
        case IF_TYPE_ETHERNET_CSMACD: f.kind = IfKind::Ethernet; break;
        case IF_TYPE_IEEE80211:       f.kind = IfKind::Wifi;     break;
        case IF_TYPE_WWANPP:
        case IF_TYPE_WWANPP2:         f.kind = IfKind::Mobile;   break;
        default:                      f.kind = IfKind::Other;    break;
        }
        StrCopy(f.alias, kAliasLen, a->FriendlyName ? a->FriendlyName : L"?");
        StrCopy(f.dnsSuffix, kDnsLen, a->DnsSuffix ? a->DnsSuffix : L"");
        // IPv4-Gateway bevorzugen, sonst erstes (IPv6) - Dual-Stack und IPv6-only.
        const IP_ADAPTER_GATEWAY_ADDRESS_LH* gw = a->FirstGatewayAddress;
        for (const IP_ADAPTER_GATEWAY_ADDRESS_LH* g = a->FirstGatewayAddress; g; g = g->Next)
            if (g->Address.lpSockaddr && g->Address.lpSockaddr->sa_family == AF_INET) { gw = g; break; }
        f.hasMac = GatewayMac(a->Luid, gw->Address.lpSockaddr, f.gwMac);
        if (f.kind == IfKind::Wifi) QueryWlan(wlan, a->Luid, f);
        ++s.n;
    }
    if (wlan) WlanCloseHandle(wlan, nullptr);
    HeapFree(heap, 0, buf);
    s.ok = true;
    return true;
}

Connectivity QueryConnectivity() {
    NL_NETWORK_CONNECTIVITY_HINT h;
    ZeroMemory(&h, sizeof h);
    if (GetNetworkConnectivityHint(&h) != NO_ERROR) return Connectivity::Unknown;
    switch (h.ConnectivityLevel) {
    case NetworkConnectivityLevelHintNone:                      return Connectivity::None;
    case NetworkConnectivityLevelHintLocalAccess:               return Connectivity::Local;
    case NetworkConnectivityLevelHintInternetAccess:            return Connectivity::Internet;
    case NetworkConnectivityLevelHintConstrainedInternetAccess: return Connectivity::Constrained;
    default:                                                    return Connectivity::Unknown;
    }
}

// =====================================================================================
// Tunnel-Dienste
// =====================================================================================

void TunnelSvcName(const wchar_t* tunnel, wchar_t* out, size_t cap) {
    swprintf_s(out, cap, L"%ls%ls", kTunnelPrefix, tunnel);
}

namespace {
TState StateOf(DWORD s) {
    switch (s) {
    case SERVICE_STOPPED:       return TState::Stopped;
    case SERVICE_START_PENDING: return TState::StartPending;
    case SERVICE_STOP_PENDING:  return TState::StopPending;
    default:                    return TState::Running;
    }
}
} // namespace

TState QueryTunnel(SC_HANDLE scm, const wchar_t* tunnel) {
    wchar_t name[64];
    TunnelSvcName(tunnel, name, _countof(name));
    SC_HANDLE h = OpenServiceW(scm, name, SERVICE_QUERY_STATUS);
    if (!h) return GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST ? TState::Missing : TState::Error;
    SERVICE_STATUS ss;
    const BOOL ok = QueryServiceStatus(h, &ss);
    CloseServiceHandle(h);
    return ok ? StateOf(ss.dwCurrentState) : TState::Error;
}

// Kurzes, begrenztes Warten nur waehrend eines Umschaltvorgangs (nie im Leerlauf).
void WaitWhile(SC_HANDLE h, DWORD pendingState, DWORD timeoutMs) {
    SERVICE_STATUS ss;
    for (DWORD waited = 0; waited < timeoutMs; waited += 100) {
        if (!QueryServiceStatus(h, &ss) || ss.dwCurrentState != pendingState) return;
        Sleep(100);
    }
}

DWORD StopTunnel(SC_HANDLE scm, const wchar_t* tunnel) {
    wchar_t name[64];
    TunnelSvcName(tunnel, name, _countof(name));
    SC_HANDLE h = OpenServiceW(scm, name, SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!h) return GetLastError();
    SERVICE_STATUS ss;
    DWORD e = NO_ERROR;
    if (!ControlService(h, SERVICE_CONTROL_STOP, &ss)) {
        e = GetLastError();
        if (e == ERROR_SERVICE_NOT_ACTIVE) e = NO_ERROR;
    } else {
        WaitWhile(h, SERVICE_STOP_PENDING, 10000);
    }
    CloseServiceHandle(h);
    return e;
}

DWORD StartTunnel(SC_HANDLE scm, const wchar_t* tunnel) {
    wchar_t name[64];
    TunnelSvcName(tunnel, name, _countof(name));
    SC_HANDLE h = OpenServiceW(scm, name, SERVICE_START | SERVICE_QUERY_STATUS);
    if (!h) return GetLastError();
    WaitWhile(h, SERVICE_STOP_PENDING, 10000);
    DWORD e = NO_ERROR;
    if (!StartServiceW(h, 0, nullptr)) {
        e = GetLastError();
        if (e == ERROR_SERVICE_ALREADY_RUNNING) e = NO_ERROR;
    }
    CloseServiceHandle(h);
    return e;
}

int FindKnown(const KnownTunnels& k, const wchar_t* name) {
    for (int i = 0; i < k.n; ++i)
        if (StrIEq(k.names[i], name)) return i;
    return -1;
}

namespace {
void AddKnown(KnownTunnels& k, const wchar_t* name) {
    if (k.n < kMaxKnown && IsValidTunnelName(name) && FindKnown(k, name) < 0)
        StrCopy(k.names[k.n++], kNameLen, name);
}
} // namespace

void EnumTunnels(SC_HANDLE scm, const Config* cfg, KnownTunnels& k) {
    k.n = 0;
    if (cfg)
        for (int i = 0; i < cfg->tunnelCount; ++i) AddKnown(k, cfg->tunnels[i]);
    if (!scm) return;
    HANDLE heap = GetProcessHeap();
    DWORD need = 0, count = 0, resume = 0;
    BYTE probe[8];
    EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, probe, 0, &need, &count,
                          &resume, nullptr);
    if (!need) return;
    BYTE* buf = static_cast<BYTE*>(HeapAlloc(heap, 0, need + 4096));
    if (!buf) return;
    resume = 0;
    if (EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, buf, need + 4096, &need,
                              &count, &resume, nullptr)) {
        const ENUM_SERVICE_STATUS_PROCESSW* e = reinterpret_cast<const ENUM_SERVICE_STATUS_PROCESSW*>(buf);
        const size_t plen = wcslen(kTunnelPrefix);
        for (DWORD i = 0; i < count; ++i)
            if (StartsWithI(e[i].lpServiceName, kTunnelPrefix)) AddKnown(k, e[i].lpServiceName + plen);
    }
    HeapFree(heap, 0, buf);
}

bool TunnelTraffic(const wchar_t* tunnel, ULONG64& rx, ULONG64& tx) {
    rx = tx = 0;
    NET_LUID luid;
    if (ConvertInterfaceAliasToLuid(tunnel, &luid) != NO_ERROR) return false;
    MIB_IF_ROW2 r;
    ZeroMemory(&r, sizeof r);
    r.InterfaceLuid = luid;
    if (GetIfEntry2(&r) != NO_ERROR) return false;
    rx = r.InOctets;
    tx = r.OutOctets;
    return true;
}

DWORD ServiceProcessId() {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return 0;
    DWORD pid = 0;
    SC_HANDLE svc = OpenServiceW(scm, kSvcName, SERVICE_QUERY_STATUS);
    if (svc) {
        SERVICE_STATUS_PROCESS ssp;
        DWORD need = 0;
        if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&ssp), sizeof ssp, &need) &&
            ssp.dwCurrentState == SERVICE_RUNNING)
            pid = ssp.dwProcessId;
        CloseServiceHandle(svc);
    }
    CloseServiceHandle(scm);
    return pid;
}

// =====================================================================================
// Named Pipe (Client)
// =====================================================================================

DWORD PipeTransact(const wchar_t* req, wchar_t* resp, DWORD respChars) {
    resp[0] = 0;
    const DWORD pid = ServiceProcessId();
    if (!pid) return ERROR_SERVICE_NOT_ACTIVE;

    HANDLE h = INVALID_HANDLE_VALUE;
    for (int attempt = 0; attempt < 2; ++attempt) {
        // SECURITY_IDENTIFICATION: ein fremder Server koennte uns hoechstens identifizieren, nicht imitieren.
        h = CreateFileW(kPipeName, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                        FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr);
        if (h != INVALID_HANDLE_VALUE) break;
        const DWORD e = GetLastError();
        if (e != ERROR_PIPE_BUSY || !WaitNamedPipeW(kPipeName, 2000)) return e;
    }
    if (h == INVALID_HANDLE_VALUE) return ERROR_PIPE_BUSY;

    ULONG serverPid = 0;
    if (!GetNamedPipeServerProcessId(h, &serverPid) || serverPid != pid) {
        CloseHandle(h);
        return ERROR_ACCESS_DENIED;   // Pipe gehoert nicht dem Dienst
    }
    DWORD mode = PIPE_READMODE_MESSAGE;
    SetNamedPipeHandleState(h, &mode, nullptr, nullptr);

    OVERLAPPED ov;
    ZeroMemory(&ov, sizeof ov);
    ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!ov.hEvent) { CloseHandle(h); return GetLastError(); }
    DWORD n = 0, e = NO_ERROR;
    const DWORD reqBytes = static_cast<DWORD>(wcslen(req) * sizeof(wchar_t));
    if (!TransactNamedPipe(h, const_cast<wchar_t*>(req), reqBytes, resp, static_cast<DWORD>((respChars - 1) * sizeof(wchar_t)), &n, &ov)) {
        e = GetLastError();
        if (e == ERROR_IO_PENDING) {
            if (WaitForSingleObject(ov.hEvent, 5000) == WAIT_OBJECT_0) {
                e = GetOverlappedResult(h, &ov, &n, FALSE) ? NO_ERROR : GetLastError();
            } else {
                CancelIo(h);
                GetOverlappedResult(h, &ov, &n, TRUE);
                e = ERROR_TIMEOUT;
            }
        }
    }
    CloseHandle(ov.hEvent);
    CloseHandle(h);
    if (e != NO_ERROR) { resp[0] = 0; return e; }
    resp[n / sizeof(wchar_t)] = 0;
    return NO_ERROR;
}

// =====================================================================================
// Version, Signatur, Pruefsummen (Update)
// =====================================================================================

void CurrentVersion(unsigned out[3]) {
    out[0] = WGAS_VERSION_MAJOR;
    out[1] = WGAS_VERSION_MINOR;
    out[2] = WGAS_VERSION_PATCH;
}

bool ReadFileVersion(const wchar_t* path, unsigned out[3]) {
    DWORD dummy = 0;
    const DWORD size = GetFileVersionInfoSizeW(path, &dummy);
    if (!size || size > 64 * 1024) return false;
    HANDLE heap = GetProcessHeap();
    void* buf = HeapAlloc(heap, 0, size);
    bool ok = false;
    VS_FIXEDFILEINFO* ffi = nullptr;
    UINT len = 0;
    if (buf && GetFileVersionInfoW(path, 0, size, buf) &&
        VerQueryValueW(buf, L"\\", reinterpret_cast<LPVOID*>(&ffi), &len) && ffi && len >= sizeof(VS_FIXEDFILEINFO)) {
        out[0] = HIWORD(ffi->dwFileVersionMS);
        out[1] = LOWORD(ffi->dwFileVersionMS);
        out[2] = HIWORD(ffi->dwFileVersionLS);
        ok = true;
    }
    if (buf) HeapFree(heap, 0, buf);
    return ok;
}

DWORD VerifyPublisher(const wchar_t* path, const wchar_t* expected, wchar_t* signer, size_t cap) {
    signer[0] = 0;
    // 1. Signatur und Zertifikatskette (inkl. Sperrpruefung) durch Windows pruefen lassen.
    WINTRUST_FILE_INFO fi;
    ZeroMemory(&fi, sizeof fi);
    fi.cbStruct = sizeof fi;
    fi.pcwszFilePath = path;
    WINTRUST_DATA wd;
    ZeroMemory(&wd, sizeof wd);
    wd.cbStruct = sizeof wd;
    wd.dwUIChoice = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
    wd.dwUnionChoice = WTD_CHOICE_FILE;
    wd.pFile = &fi;
    wd.dwStateAction = WTD_STATEACTION_VERIFY;
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    const LONG trust = WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &action, &wd);
    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &action, &wd);

    // 2. Herausgeber (Common Name des Signaturzertifikats) auslesen.
    HCERTSTORE store = nullptr;
    HCRYPTMSG msg = nullptr;
    if (CryptQueryObject(CERT_QUERY_OBJECT_FILE, path, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                         CERT_QUERY_FORMAT_FLAG_BINARY, 0, nullptr, nullptr, nullptr, &store, &msg, nullptr)) {
        DWORD n = 0;
        HANDLE heap = GetProcessHeap();
        if (CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &n) && n) {
            CMSG_SIGNER_INFO* si = static_cast<CMSG_SIGNER_INFO*>(HeapAlloc(heap, 0, n));
            if (si && CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, si, &n)) {
                CERT_INFO ci;
                ZeroMemory(&ci, sizeof ci);
                ci.Issuer = si->Issuer;
                ci.SerialNumber = si->SerialNumber;
                PCCERT_CONTEXT cert = CertFindCertificateInStore(store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
                                                                 CERT_FIND_SUBJECT_CERT, &ci, nullptr);
                if (cert) {
                    CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, signer, static_cast<DWORD>(cap));
                    CertFreeCertificateContext(cert);
                }
            }
            if (si) HeapFree(heap, 0, si);
        }
        CryptMsgClose(msg);
        CertCloseStore(store, 0);
    }
    if (trust != ERROR_SUCCESS) return static_cast<DWORD>(trust);
    return StrEq(signer, expected) ? NO_ERROR : static_cast<DWORD>(TRUST_E_SUBJECT_NOT_TRUSTED);
}

bool Sha256File(const wchar_t* path, wchar_t* hex, size_t cap) {
    if (cap < 65) return false;
    hex[0] = 0;
    HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (f == INVALID_HANDLE_VALUE) return false;
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE h = nullptr;
    bool ok = BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0)) &&
              BCRYPT_SUCCESS(BCryptCreateHash(alg, &h, nullptr, 0, nullptr, 0, 0));
    static BYTE buf[64 * 1024];
    DWORD n = 0;
    while (ok && ReadFile(f, buf, sizeof buf, &n, nullptr) && n > 0)
        ok = BCRYPT_SUCCESS(BCryptHashData(h, buf, n, 0));
    BYTE digest[32];
    ok = ok && BCRYPT_SUCCESS(BCryptFinishHash(h, digest, sizeof digest, 0));
    if (h) BCryptDestroyHash(h);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    CloseHandle(f);
    if (!ok) return false;
    for (int i = 0; i < 32; ++i) swprintf_s(hex + i * 2, cap - static_cast<size_t>(i) * 2, L"%02x", static_cast<unsigned>(digest[i]));
    return true;
}

const wchar_t* NativeArch() {
    USHORT process = 0, native = 0;
    if (IsWow64Process2(GetCurrentProcess(), &process, &native) && native == IMAGE_FILE_MACHINE_ARM64) return L"arm64";
#if defined(_M_ARM64)
    return L"arm64";
#else
    return L"x64";
#endif
}

} // namespace wgas
