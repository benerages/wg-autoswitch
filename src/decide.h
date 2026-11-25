#pragma once
// decide.h - reine Entscheidungslogik von WG-AutoSwitch.
//
// Keine Windows-Header, keine STL, keine Allokationen: Die Datei ist mit jedem
// C++20-Compiler uebersetzbar und wird in tests/test_decide.cpp ohne Windows getestet.
//
// Modell
//   * Jede aktive Netzschnittstelle (mit Standard-Gateway) liefert Merkmale (IfInfo).
//   * Regeln [network.<name>] aus config.ini ordnen einem Netz einen Tunnel zu
//     oder "none" (= vertrautes Netz, kein Tunnel). Erste passende Regel gewinnt.
//   * Unbekannte Netze bekommen den Standardtunnel (default_tunnel).
//   * Es laeuft hoechstens EIN Tunnel gleichzeitig (verhindert Routing-Konflikte
//     bei AllowedIPs = 0.0.0.0/0).

namespace wgas {

constexpr int kNameLen    = 33;   // Tunnelname: max. 32 Zeichen (Vorgabe WireGuard fuer Windows)
constexpr int kSsidLen    = 33;   // SSID: max. 32 Byte -> max. 32 UTF-16-Einheiten
constexpr int kDnsLen     = 256;  // DNS-Suffix: max. 255 Zeichen
constexpr int kRuleLen    = 48;   // Regelname (Teil nach "network.")
constexpr int kAliasLen   = 64;   // Anzeigename der Schnittstelle
constexpr int kMaxTunnels = 16;
constexpr int kMaxRules   = 32;
constexpr int kMaxIfs     = 16;
constexpr int kNoTunnel   = -1;   // "kein Tunnel"

enum class IfKind : unsigned char { Other, Ethernet, Wifi, Mobile };
enum class Connectivity : unsigned char { Unknown, None, Local, Constrained, Internet };

// Bewusst ohne Default-Member-Initialisierer: globale Instanzen landen so in .bss
// statt als initialisierte Daten im Binary (Groessenziel < 100 KB).
struct IfInfo {
    IfKind        kind;
    bool          hasMac;
    unsigned char gwMac[6];
    bool          hasSsid;
    wchar_t       ssid[kSsidLen];
    bool          hasBssid;              // MAC des WLAN-Access-Points
    unsigned char bssid[6];
    wchar_t       dnsSuffix[kDnsLen];
    wchar_t       alias[kAliasLen];      // nur fuer Anzeige/Protokoll
};

struct Rule {
    wchar_t       name[kRuleLen];
    bool          hasKind;  IfKind kind;
    bool          hasMac;   unsigned char gwMac[6];
    bool          hasDns;   wchar_t dnsSuffix[kDnsLen];
    bool          hasSsid;  wchar_t ssid[kSsidLen];
    bool          hasBssid; unsigned char bssid[6];
    int           tunnel;                // Index in Config::tunnels oder kNoTunnel
};

struct Config {
    unsigned debounceMs;
    int      defaultTunnel;              // fuer unbekannte Netze und Fail-safe
    bool     noNetworkOn;                // no_network = on -> Tunnel auch ohne Netz an
    bool     captiveWait;                // captive_portal = wait
    int      tunnelCount;
    wchar_t  tunnels[kMaxTunnels][kNameLen];
    int      ruleCount;
    Rule     rules[kMaxRules];
};

struct Decision {
    int  tunnel;        // Index oder kNoTunnel
    bool captiveHold;   // Tunnel wegen Captive Portal zurueckgehalten
    bool failSafe;      // Zustand nicht bestimmbar -> Standardtunnel
};

// ------------------------------------------------------------ kleine Helfer

using SizeT = decltype(sizeof 0);   // size_t ohne Header

inline void ZeroBytes(void* p, SizeT n) {
    unsigned char* b = static_cast<unsigned char*>(p);
    while (n--) *b++ = 0;
}

inline void ResetConfig(Config& c) {
    ZeroBytes(&c, sizeof c);
    c.debounceMs    = 2500;
    c.defaultTunnel = kNoTunnel;
    c.noNetworkOn   = false;
    c.captiveWait   = true;
}

inline int StrLen(const wchar_t* s) { int n = 0; while (s[n]) ++n; return n; }

inline void StrCopy(wchar_t* dst, int cap, const wchar_t* src) {
    int i = 0;
    for (; i < cap - 1 && src[i]; ++i) dst[i] = src[i];
    dst[i] = 0;
}

inline wchar_t AsciiLower(wchar_t c) {
    return (c >= L'A' && c <= L'Z') ? static_cast<wchar_t>(c - L'A' + L'a') : c;
}

inline bool StrEq(const wchar_t* a, const wchar_t* b) {
    while (*a && *a == *b) { ++a; ++b; }
    return *a == *b;
}

inline bool StrIEq(const wchar_t* a, const wchar_t* b) {
    while (*a && AsciiLower(*a) == AsciiLower(*b)) { ++a; ++b; }
    return AsciiLower(*a) == AsciiLower(*b);
}

inline bool StartsWithI(const wchar_t* s, const wchar_t* prefix) {
    while (*prefix) {
        if (AsciiLower(*s) != AsciiLower(*prefix)) return false;
        ++s; ++prefix;
    }
    return true;
}

inline int HexVal(wchar_t c) {
    if (c >= L'0' && c <= L'9') return c - L'0';
    if (c >= L'a' && c <= L'f') return c - L'a' + 10;
    if (c >= L'A' && c <= L'F') return c - L'A' + 10;
    return -1;
}

// "00:11:22:aa:bb:cc" oder "00-11-22-AA-BB-CC"
inline bool ParseMac(const wchar_t* s, unsigned char out[6]) {
    for (int i = 0; i < 6; ++i) {
        const int hi = HexVal(s[0]);
        const int lo = hi < 0 ? -1 : HexVal(s[1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = static_cast<unsigned char>(hi * 16 + lo);
        s += 2;
        if (i < 5) {
            if (*s != L':' && *s != L'-') return false;
            ++s;
        }
    }
    return *s == 0;
}

inline bool MacEq(const unsigned char* a, const unsigned char* b) {
    for (int i = 0; i < 6; ++i) if (a[i] != b[i]) return false;
    return true;
}

inline bool MacIsZero(const unsigned char* m) {
    for (int i = 0; i < 6; ++i) if (m[i]) return false;
    return true;
}

// Nur Ziffern, max. 9 Stellen (kein Ueberlauf moeglich).
inline bool ParseUInt(const wchar_t* s, unsigned& out) {
    unsigned v = 0; int n = 0;
    for (; s[n]; ++n) {
        if (s[n] < L'0' || s[n] > L'9' || n >= 9) return false;
        v = v * 10 + static_cast<unsigned>(s[n] - L'0');
    }
    if (n == 0) return false;
    out = v;
    return true;
}

// Erlaubte Zeichen fuer Tunnelnamen von WireGuard fuer Windows: [A-Za-z0-9_=+.-], 1..32
inline bool IsValidTunnelName(const wchar_t* s) {
    int n = 0;
    for (; s[n]; ++n) {
        const wchar_t c = s[n];
        const bool ok = (c >= L'a' && c <= L'z') || (c >= L'A' && c <= L'Z') ||
                        (c >= L'0' && c <= L'9') || c == L'_' || c == L'=' ||
                        c == L'+' || c == L'.' || c == L'-';
        if (!ok || n >= kNameLen - 1) return false;
    }
    return n > 0 && !StrIEq(s, L"none");
}

inline bool IsValidRuleName(const wchar_t* s) {
    int n = 0;
    for (; s[n]; ++n) {
        const wchar_t c = s[n];
        const bool ok = (c >= L'a' && c <= L'z') || (c >= L'A' && c <= L'Z') ||
                        (c >= L'0' && c <= L'9') || c == L'_' || c == L'.' || c == L'-';
        if (!ok || n >= kRuleLen - 1) return false;
    }
    return n > 0;
}

inline bool IsValidDnsSuffix(const wchar_t* s) {
    int n = 0;
    for (; s[n]; ++n) {
        const wchar_t c = s[n];
        const bool ok = (c >= L'a' && c <= L'z') || (c >= L'A' && c <= L'Z') ||
                        (c >= L'0' && c <= L'9') || c == L'.' || c == L'-';
        if (!ok || n >= kDnsLen - 1) return false;
    }
    return n > 0;
}

// ------------------------------------------------------------ Versionen

// "1.2.3" oder "v1.2.3" -> {1,2,3}. Genau drei Zahlen, jeweils hoechstens 5 Stellen.
inline bool ParseVersion(const wchar_t* s, unsigned out[3]) {
    if (*s == L'v' || *s == L'V') ++s;
    for (int i = 0; i < 3; ++i) {
        unsigned v = 0;
        int digits = 0;
        while (*s >= L'0' && *s <= L'9') {
            if (++digits > 5) return false;
            v = v * 10 + static_cast<unsigned>(*s - L'0');
            ++s;
        }
        if (!digits) return false;
        out[i] = v;
        if (i < 2) {
            if (*s != L'.') return false;
            ++s;
        }
    }
    return *s == 0;
}

// <0: a aelter, 0: gleich, >0: a neuer
inline int CompareVersion(const unsigned a[3], const unsigned b[3]) {
    for (int i = 0; i < 3; ++i)
        if (a[i] != b[i]) return a[i] < b[i] ? -1 : 1;
    return 0;
}

// ------------------------------------------------------------ Regeln

// Alle in der Regel angegebenen Merkmale muessen passen. Eine Regel ohne
// Merkmal passt nie (wird beim Laden ohnehin abgelehnt).
inline bool RuleMatches(const Rule& r, const IfInfo& f) {
    int criteria = 0;
    if (r.hasKind) { ++criteria; if (r.kind != f.kind) return false; }
    if (r.hasMac)  { ++criteria; if (!f.hasMac || !MacEq(r.gwMac, f.gwMac)) return false; }
    if (r.hasDns)  { ++criteria; if (!StrIEq(r.dnsSuffix, f.dnsSuffix)) return false; }
    if (r.hasSsid) { ++criteria; if (!f.hasSsid || !StrEq(r.ssid, f.ssid)) return false; }
    if (r.hasBssid) { ++criteria; if (!f.hasBssid || !MacEq(r.bssid, f.bssid)) return false; }
    return criteria > 0;
}

// Sicherheitsregel: Eine Regel, die den Tunnel AUSSCHALTET (tunnel = none),
// braucht die Gateway-MAC plus mindestens ein weiteres Merkmal (DNS-Suffix, SSID
// oder BSSID). Eine SSID allein kann jeder faelschen. Regeln, die einen Tunnel
// EINSCHALTEN, sind unkritisch und duerfen ein einzelnes Merkmal haben.
inline bool RuleStrongEnough(const Rule& r) {
    if (!(r.hasKind || r.hasMac || r.hasDns || r.hasSsid || r.hasBssid)) return false;
    if (r.tunnel != kNoTunnel) return true;
    return r.hasMac && (r.hasDns || r.hasSsid || r.hasBssid);
}

inline int MatchRule(const Config& c, const IfInfo& f) {
    for (int i = 0; i < c.ruleCount; ++i)
        if (RuleMatches(c.rules[i], f)) return i;
    return -1;
}

// Fingerabdruck der verbundenen Netze (FNV-1a, 64 Bit). Manuelles Schalten gilt,
// bis sich dieser Wert aendert. Die BSSID fliesst bewusst NICHT ein: WLAN-Roaming
// zwischen Access Points ist kein Netzwechsel.
inline unsigned long long NetFingerprint(const IfInfo* ifs, int n) {
    unsigned long long h = 1469598103934665603ull;
    auto mix = [&h](unsigned v) { h ^= v; h *= 1099511628211ull; };
    for (int i = 0; i < n; ++i) {
        const IfInfo& f = ifs[i];
        mix(static_cast<unsigned>(f.kind) + 1u);
        if (f.hasMac) for (int k = 0; k < 6; ++k) mix(f.gwMac[k]);
        for (const wchar_t* p = f.dnsSuffix; *p; ++p) mix(static_cast<unsigned>(AsciiLower(*p)));
        mix(0xFFu);
        if (f.hasSsid) for (const wchar_t* p = f.ssid; *p; ++p) mix(static_cast<unsigned>(*p));
        mix(0xFEu);
    }
    return h;
}

// Kernentscheid (F2-F5, Captive Portal).
//   stateKnown = false  -> Netzwerk- oder Konfigurationszustand unklar -> Fail-safe (F4)
//   n == 0              -> kein Netz -> Tunnel aus (F3), ausser no_network = on
//   mehrere Schnittstellen (F5): Tunnel nur aus, wenn ALLE ein "none" ergeben.
//     Verlangen Schnittstellen verschiedene Tunnel -> Standardtunnel (Konflikt = Fail-safe).
inline Decision Decide(const Config& c, const IfInfo* ifs, int n, Connectivity conn, bool stateKnown) {
    Decision d{ kNoTunnel, false, false };
    if (!stateKnown || n < 0) {
        d.tunnel = c.defaultTunnel;
        d.failSafe = true;
        return d;
    }
    if (n == 0) {
        d.tunnel = c.noNetworkOn ? c.defaultTunnel : kNoTunnel;
        return d;
    }
    int chosen = kNoTunnel;
    bool conflict = false;
    for (int i = 0; i < n; ++i) {
        const int r = MatchRule(c, ifs[i]);
        const int want = (r >= 0) ? c.rules[r].tunnel : c.defaultTunnel;
        if (want == kNoTunnel) continue;
        if (chosen == kNoTunnel) chosen = want;
        else if (chosen != want) conflict = true;
    }
    d.tunnel = conflict ? c.defaultTunnel : chosen;

    // Captive Portal (Hotel, Zug): Anmeldung ist nur ohne Tunnel moeglich. Erst wenn
    // Windows (NLA) vollen Internetzugang meldet, kommt der Tunnel.
    if (d.tunnel != kNoTunnel && conn == Connectivity::Constrained && c.captiveWait) {
        d.tunnel = kNoTunnel;
        d.captiveHold = true;
    }
    return d;
}

} // namespace wgas
