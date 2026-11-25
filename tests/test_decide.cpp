// test_decide.cpp - Unit-Tests der reinen Entscheidungslogik (ohne Windows-APIs).
// Windows:  build.cmd test
// Linux:    g++ -std=c++20 -Wall -Wextra -Werror tests/test_decide.cpp -o test && ./test
#include "../src/decide.h"
#include <cstdio>

using namespace wgas;

static int g_fail = 0, g_run = 0;
#define CHECK(cond) do { ++g_run; if (!(cond)) { std::printf("FEHLER %s:%d: %s\n", __FILE__, __LINE__, #cond); ++g_fail; } } while (0)

static const unsigned char kHomeMac[6]   = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
static const unsigned char kOfficeMac[6] = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
static const unsigned char kOtherMac[6]  = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };

static Config g_cfg;

static void Mac(unsigned char* dst, const unsigned char* src) { for (int i = 0; i < 6; ++i) dst[i] = src[i]; }

// Tunnel 0 = wg-home (Standard), 1 = wg-office
static void SetupConfig() {
    ResetConfig(g_cfg);
    StrCopy(g_cfg.tunnels[0], kNameLen, L"wg-home");
    StrCopy(g_cfg.tunnels[1], kNameLen, L"wg-office");
    g_cfg.tunnelCount = 2;
    g_cfg.defaultTunnel = 0;

    Rule& lan = g_cfg.rules[0];             // Zuhause LAN -> kein Tunnel
    StrCopy(lan.name, kRuleLen, L"home-lan");
    lan.hasKind = true; lan.kind = IfKind::Ethernet;
    lan.hasMac = true;  Mac(lan.gwMac, kHomeMac);
    lan.hasDns = true;  StrCopy(lan.dnsSuffix, kDnsLen, L"home.lan");
    lan.tunnel = kNoTunnel;

    Rule& wlan = g_cfg.rules[1];            // Zuhause WLAN -> kein Tunnel
    StrCopy(wlan.name, kRuleLen, L"home-wlan");
    wlan.hasKind = true; wlan.kind = IfKind::Wifi;
    wlan.hasSsid = true; StrCopy(wlan.ssid, kSsidLen, L"MeinWLAN");
    wlan.hasMac = true;  Mac(wlan.gwMac, kHomeMac);
    wlan.tunnel = kNoTunnel;

    Rule& office = g_cfg.rules[2];          // Buero -> wg-office
    StrCopy(office.name, kRuleLen, L"office");
    office.hasMac = true; Mac(office.gwMac, kOfficeMac);
    office.hasDns = true; StrCopy(office.dnsSuffix, kDnsLen, L"corp.example");
    office.tunnel = 1;

    g_cfg.ruleCount = 3;
}

static IfInfo MakeIf(IfKind k, const unsigned char* mac, const wchar_t* dns, const wchar_t* ssid) {
    IfInfo f;
    ZeroBytes(&f, sizeof f);
    f.kind = k;
    if (mac) { f.hasMac = true; Mac(f.gwMac, mac); }
    StrCopy(f.dnsSuffix, kDnsLen, dns ? dns : L"");
    if (ssid) { f.hasSsid = true; StrCopy(f.ssid, kSsidLen, ssid); }
    return f;
}

int main() {
    SetupConfig();
    const auto Inet = Connectivity::Internet;

    // F3: kein Netz -> aus; no_network=on -> an
    {
        Decision d = Decide(g_cfg, nullptr, 0, Connectivity::None, true);
        CHECK(d.tunnel == kNoTunnel);
        g_cfg.noNetworkOn = true;
        d = Decide(g_cfg, nullptr, 0, Connectivity::None, true);
        CHECK(d.tunnel == 0);
        g_cfg.noNetworkOn = false;
    }
    // Zuhause LAN -> aus
    {
        IfInfo f[1] = { MakeIf(IfKind::Ethernet, kHomeMac, L"home.lan", nullptr) };
        CHECK(Decide(g_cfg, f, 1, Inet, true).tunnel == kNoTunnel);
    }
    // DNS-Suffix ohne Gross-/Kleinschreibung
    {
        IfInfo f[1] = { MakeIf(IfKind::Ethernet, kHomeMac, L"HOME.Lan", nullptr) };
        CHECK(Decide(g_cfg, f, 1, Inet, true).tunnel == kNoTunnel);
    }
    // Gefaelschtes Netz: gleicher DNS-Suffix, andere Gateway-MAC -> Standardtunnel
    {
        IfInfo f[1] = { MakeIf(IfKind::Ethernet, kOtherMac, L"home.lan", nullptr) };
        CHECK(Decide(g_cfg, f, 1, Inet, true).tunnel == 0);
    }
    // Gefaelschte SSID ohne passende MAC -> Standardtunnel
    {
        IfInfo f[1] = { MakeIf(IfKind::Wifi, kOtherMac, L"", L"MeinWLAN") };
        CHECK(Decide(g_cfg, f, 1, Inet, true).tunnel == 0);
    }
    // MAC nicht ermittelbar (F4) -> Standardtunnel
    {
        IfInfo f[1] = { MakeIf(IfKind::Wifi, nullptr, L"", L"MeinWLAN") };
        CHECK(Decide(g_cfg, f, 1, Inet, true).tunnel == 0);
    }
    // SSID ist case-sensitiv
    {
        IfInfo f[1] = { MakeIf(IfKind::Wifi, kHomeMac, L"", L"meinwlan") };
        CHECK(Decide(g_cfg, f, 1, Inet, true).tunnel == 0);
    }
    // Zuhause WLAN -> aus
    {
        IfInfo f[1] = { MakeIf(IfKind::Wifi, kHomeMac, L"", L"MeinWLAN") };
        CHECK(Decide(g_cfg, f, 1, Inet, true).tunnel == kNoTunnel);
    }
    // F5: Docking zuhause (LAN + WLAN vertraut) -> aus
    {
        IfInfo f[2] = { MakeIf(IfKind::Ethernet, kHomeMac, L"home.lan", nullptr),
                        MakeIf(IfKind::Wifi, kHomeMac, L"", L"MeinWLAN") };
        CHECK(Decide(g_cfg, f, 2, Inet, true).tunnel == kNoTunnel);
    }
    // F5: LAN vertraut + WLAN unbekannt -> Standardtunnel
    {
        IfInfo f[2] = { MakeIf(IfKind::Ethernet, kHomeMac, L"home.lan", nullptr),
                        MakeIf(IfKind::Wifi, kOtherMac, L"", L"Hotel") };
        CHECK(Decide(g_cfg, f, 2, Inet, true).tunnel == 0);
    }
    // Buero -> wg-office
    {
        IfInfo f[1] = { MakeIf(IfKind::Ethernet, kOfficeMac, L"corp.example", nullptr) };
        CHECK(Decide(g_cfg, f, 1, Inet, true).tunnel == 1);
    }
    // Buero + vertrautes Heimnetz -> wg-office
    {
        IfInfo f[2] = { MakeIf(IfKind::Ethernet, kOfficeMac, L"corp.example", nullptr),
                        MakeIf(IfKind::Wifi, kHomeMac, L"", L"MeinWLAN") };
        CHECK(Decide(g_cfg, f, 2, Inet, true).tunnel == 1);
    }
    // Konflikt Buero + unbekannt -> Standardtunnel
    {
        IfInfo f[2] = { MakeIf(IfKind::Ethernet, kOfficeMac, L"corp.example", nullptr),
                        MakeIf(IfKind::Mobile, kOtherMac, L"", nullptr) };
        Decision d = Decide(g_cfg, f, 2, Inet, true);
        CHECK(d.tunnel == 0);
    }
    // F4: Zustand unbekannt -> Standardtunnel, failSafe
    {
        IfInfo f[1] = { MakeIf(IfKind::Ethernet, kHomeMac, L"home.lan", nullptr) };
        Decision d = Decide(g_cfg, f, 1, Inet, false);
        CHECK(d.tunnel == 0 && d.failSafe);
    }
    // Captive Portal: unbekanntes Netz, eingeschraenkt -> warten
    {
        IfInfo f[1] = { MakeIf(IfKind::Wifi, kOtherMac, L"", L"Hotel-Gast") };
        Decision d = Decide(g_cfg, f, 1, Connectivity::Constrained, true);
        CHECK(d.tunnel == kNoTunnel && d.captiveHold);
        d = Decide(g_cfg, f, 1, Connectivity::Internet, true);
        CHECK(d.tunnel == 0 && !d.captiveHold);
        g_cfg.captiveWait = false;
        d = Decide(g_cfg, f, 1, Connectivity::Constrained, true);
        CHECK(d.tunnel == 0 && !d.captiveHold);
        g_cfg.captiveWait = true;
    }
    // Captive-Status ist irrelevant, wenn Tunnel ohnehin aus
    {
        IfInfo f[1] = { MakeIf(IfKind::Ethernet, kHomeMac, L"home.lan", nullptr) };
        Decision d = Decide(g_cfg, f, 1, Connectivity::Constrained, true);
        CHECK(d.tunnel == kNoTunnel && !d.captiveHold);
    }
    // Hotspot vom Handy (Mobilfunk/USB) -> unbekannt -> Standardtunnel
    {
        IfInfo f[1] = { MakeIf(IfKind::Ethernet, kOtherMac, L"", nullptr) };
        CHECK(Decide(g_cfg, f, 1, Connectivity::Local, true).tunnel == 0);
    }
    // ParseMac
    {
        unsigned char m[6];
        CHECK(ParseMac(L"00:11:22:33:44:55", m) && MacEq(m, kHomeMac));
        CHECK(ParseMac(L"AA-BB-CC-DD-EE-FF", m) && MacEq(m, kOfficeMac));
        CHECK(!ParseMac(L"00:11:22:33:44", m));
        CHECK(!ParseMac(L"00:11:22:33:44:55:66", m));
        CHECK(!ParseMac(L"00:11:22:33:44:5g", m));
        CHECK(!ParseMac(L"", m));
    }
    // RuleStrongEnough
    {
        Rule r; ZeroBytes(&r, sizeof r); r.tunnel = kNoTunnel;
        r.hasSsid = true;                 CHECK(!RuleStrongEnough(r));  // nur SSID
        r.hasSsid = false; r.hasMac = true; CHECK(!RuleStrongEnough(r)); // nur MAC
        r.hasSsid = true;                 CHECK(RuleStrongEnough(r));   // MAC + SSID
        r.hasSsid = false; r.hasDns = true; CHECK(RuleStrongEnough(r));  // MAC + DNS
        r.hasMac = false; r.hasSsid = true; CHECK(!RuleStrongEnough(r)); // DNS + SSID ohne MAC
        r.tunnel = 1;                     CHECK(RuleStrongEnough(r));   // Tunnel-Regel
        Rule e; ZeroBytes(&e, sizeof e); e.tunnel = 1; CHECK(!RuleStrongEnough(e)); // leer
    }
    // Namen und Zahlen
    {
        CHECK(IsValidTunnelName(L"wg-home"));
        CHECK(IsValidTunnelName(L"a_b=c+d.e-f"));
        CHECK(!IsValidTunnelName(L""));
        CHECK(!IsValidTunnelName(L"none"));
        CHECK(!IsValidTunnelName(L"mit leerzeichen"));
        CHECK(!IsValidTunnelName(L"..\\x"));
        CHECK(!IsValidTunnelName(L"123456789012345678901234567890123")); // 33 Zeichen
        CHECK(IsValidTunnelName(L"12345678901234567890123456789012"));   // 32 Zeichen
        CHECK(IsValidDnsSuffix(L"home.lan") && !IsValidDnsSuffix(L"home lan"));
        unsigned v = 0;
        CHECK(ParseUInt(L"2500", v) && v == 2500);
        CHECK(!ParseUInt(L"25x", v) && !ParseUInt(L"", v) && !ParseUInt(L"1234567890", v));
    }

    // BSSID als zweites Merkmal
    {
        static const unsigned char kAp[6] = { 0x10, 0x20, 0x30, 0x40, 0x50, 0x60 };
        Rule r; ZeroBytes(&r, sizeof r); r.tunnel = kNoTunnel;
        r.hasMac = true; Mac(r.gwMac, kHomeMac);
        r.hasBssid = true; Mac(r.bssid, kAp);
        CHECK(RuleStrongEnough(r));
        IfInfo f = MakeIf(IfKind::Wifi, kHomeMac, L"", L"X");
        CHECK(!RuleMatches(r, f));                 // BSSID fehlt
        f.hasBssid = true; Mac(f.bssid, kAp);
        CHECK(RuleMatches(r, f));
        f.bssid[5] = 0x61;
        CHECK(!RuleMatches(r, f));                 // anderer Access Point
    }
    // Fingerabdruck: Roaming (andere BSSID) aendert ihn nicht, anderes Netz schon
    {
        IfInfo a[1] = { MakeIf(IfKind::Wifi, kHomeMac, L"home.lan", L"MeinWLAN") };
        IfInfo b[1] = { a[0] };
        b[0].hasBssid = true; b[0].bssid[0] = 1;
        CHECK(NetFingerprint(a, 1) == NetFingerprint(b, 1));
        IfInfo c[1] = { MakeIf(IfKind::Wifi, kOtherMac, L"home.lan", L"MeinWLAN") };
        CHECK(NetFingerprint(a, 1) != NetFingerprint(c, 1));
        IfInfo d[1] = { MakeIf(IfKind::Wifi, kHomeMac, L"HOME.LAN", L"MeinWLAN") };
        CHECK(NetFingerprint(a, 1) == NetFingerprint(d, 1));  // DNS-Suffix ohne Gross/Klein
        CHECK(NetFingerprint(a, 1) != NetFingerprint(a, 0));
    }

    std::printf("%d Pruefungen, %d Fehler\n", g_run, g_fail);
    return g_fail ? 1 : 0;
}
