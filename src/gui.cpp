// gui.cpp - WG-AutoSwitch Oberflaeche (wgas-gui.exe): Tray-Symbol und Fenster.
//
// Zwei Rollen in einem Programm:
//   wgas-gui.exe [--tray]           normale Oberflaeche OHNE Adminrechte. Liest den Zustand ueber
//                                   die Named Pipe des Dienstes; verbinden/trennen/pausieren ebenso.
//   wgas-gui.exe --edit <tunnel>    Tunnel-Editor, nur per UAC (Admin) gestartet: liest/schreibt
//   wgas-gui.exe --new [<datei>]    die .conf im geschuetzten Ordner und importiert ueber
//   wgas-gui.exe --clip             "wgas.exe --gui import". Private Schluessel verlassen nie
//                                   den Admin-Prozess.
// Konfigurationsaenderungen (Regeln) laufen als "wgas.exe --gui setconfig <datei>" per UAC.
//
// Energie: Ist das Fenster verborgen, wartet die Oberflaeche nur auf Fensternachrichten und das
// Signal "Global\WgAutoSwitchState" des Dienstes - kein Timer. Nur bei sichtbarem Fenster
// aktualisiert ein 2-s-Timer die Datenzaehler.

#include "common.h"
#include "update.h"
#include <commctrl.h>
#include <commdlg.h>
#include <shellapi.h>
#include <stdlib.h>
#include <math.h>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(linker, "\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

using namespace wgas;

namespace {

// =====================================================================================
// Konstanten
// =====================================================================================

constexpr wchar_t kMainClass[]   = L"WgAutoSwitchGui";
constexpr wchar_t kFormClass[]   = L"WgAutoSwitchForm";
constexpr wchar_t kRunKey[]      = L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
constexpr wchar_t kRunValue[]    = L"WgAutoSwitchGui";
constexpr wchar_t kUserKey[]     = L"Software\\WgAutoSwitch";
constexpr wchar_t kTitle[]       = L"WG-AutoSwitch";

enum : UINT { WM_APP_TRAY = WM_APP + 1, WM_APP_SHOW, WM_APP_ELEVDONE, WM_APP_UPDCHECK, WM_APP_UPDREADY };
enum : UINT_PTR { TIMER_REFRESH = 1, TIMER_RECONNECT = 2, TIMER_UPDATE = 3 };
constexpr UINT kNinBalloonUserClick = WM_USER + 5;   // NIN_BALLOONUSERCLICK

enum : int {
    IDC_TAB = 100, IDC_STATUS, IDC_INSTALL, IDC_TUNLIST, IDC_CONNECT, IDC_DISCONNECT, IDC_AUTO,
    IDC_IMPORT, IDC_CLIP, IDC_EDIT, IDC_REMOVE,
    IDC_NETINFO, IDC_TRUST, IDC_MAPNET, IDC_RULES, IDC_RNEW, IDC_REDIT, IDC_RDEL, IDC_RUP, IDC_RDOWN,
    IDC_DEFLBL, IDC_DEFAULT, IDC_NONET, IDC_CAPTIVE, IDC_DEBLBL, IDC_DEBOUNCE, IDC_APPLY,
    IDC_F_NAME = 300, IDC_F_TYPE, IDC_F_SSID, IDC_F_BSSID, IDC_F_MAC, IDC_F_DNS, IDC_F_TUNNEL, IDC_F_TEXT, IDC_F_HINT,
};
enum : UINT {
    ID_TRAY_OPEN = 1000, ID_TRAY_DISCONNECT, ID_TRAY_AUTO, ID_TRAY_PAUSE15, ID_TRAY_PAUSE60, ID_TRAY_PAUSE480,
    ID_TRAY_RESUME, ID_TRAY_AUTOSTART, ID_TRAY_EXIT, ID_TRAY_LANG_AUTO, ID_TRAY_LANG_DE, ID_TRAY_LANG_EN,
    ID_TRAY_UPDATE_CHECK, ID_TRAY_UPDATE_AUTO, ID_TRAY_UPDATE_INSTALL, ID_TRAY_ABOUT,
    ID_TRAY_WG_DOWNLOAD,
    ID_TRAY_TUNNEL0 = 1100,
};

// =====================================================================================
// Zustand vom Dienst (Antwort auf "status", Format siehe wgas.cpp BuildStatus)
// =====================================================================================

struct TunInfo {
    wchar_t name[kNameLen];
    int     state;          // TState
    ULONG64 rx, tx;
};

struct Model {
    bool      connected;    // Pipe erreichbar
    DWORD     err;
    bool      installed;    // Dienst vorhanden
    wchar_t   mode[16];     // auto | paused | manual
    ULONGLONG pausedUntil;
    wchar_t   manualTunnel[kNameLen];
    bool      cfgValid;
    wchar_t   cfgErr[512];
    wchar_t   target[kNameLen];
    bool      captive, failsafe;
    int       conn;
    wchar_t   why[768];
    int       nIf;
    IfInfo    ifs[kMaxIfs];
    wchar_t   ifRule[kMaxIfs][kRuleLen];
    int       nTun;
    TunInfo   tun[kMaxKnown];
    Config    cfg;          // Regeln und Optionen, wie der Dienst sie verwendet
    wchar_t   svcVersion[16];
};

Model  g_m;
Config g_edit;          // in der Oberflaeche bearbeitete Kopie von g_m.cfg
bool   g_dirty;         // g_edit weicht ab und ist noch nicht uebernommen

// =====================================================================================
// Fenster, Schrift, DPI
// =====================================================================================

HINSTANCE g_inst;
HWND      g_main, g_tab;
int       g_dpi = 96;
HFONT     g_font, g_mono;
HICON     g_icons[4];   // 0 aus (grau), 1 an (gruen), 2 Hinweis (orange), 3 Fehler (rot)
int       g_iconDpi;
NOTIFYICONDATAW g_nid;
UINT      g_taskbarCreated;
HANDLE    g_stateEv;
int       g_page;       // 0 Tunnel, 1 Auto-Tunneling
HANDLE    g_mutex;      // Einzelinstanz; beim Sprachwechsel vor dem Neustart freigegeben
UpdateInfo g_upd;       // Ergebnis der letzten Update-Pruefung
bool      g_updChecking, g_updDownloading;

int S(int v) { return MulDiv(v, g_dpi, 96); }

void CreateFonts() {
    if (g_font) DeleteObject(g_font);
    if (g_mono) DeleteObject(g_mono);
    NONCLIENTMETRICSW ncm;
    ZeroMemory(&ncm, sizeof ncm);
    ncm.cbSize = sizeof ncm;
    SystemParametersInfoForDpi(SPI_GETNONCLIENTMETRICS, sizeof ncm, &ncm, 0, static_cast<UINT>(g_dpi));
    g_font = CreateFontIndirectW(&ncm.lfMessageFont);
    LOGFONTW lf = ncm.lfMessageFont;
    lf.lfPitchAndFamily = FIXED_PITCH | FF_MODERN;
    swprintf_s(lf.lfFaceName, LF_FACESIZE, L"Consolas");
    g_mono = CreateFontIndirectW(&lf);
}

BOOL CALLBACK SetFontProc(HWND h, LPARAM font) {
    const int id = GetDlgCtrlID(h);
    SendMessageW(h, WM_SETFONT, static_cast<WPARAM>(id == IDC_F_TEXT ? reinterpret_cast<LPARAM>(g_mono) : font), TRUE);
    return TRUE;
}

HWND Ctl(HWND parent, const wchar_t* cls, const wchar_t* text, DWORD style, int id, DWORD ex = 0) {
    HWND h = CreateWindowExW(ex, cls, text, WS_CHILD | WS_VISIBLE | style, 0, 0, 0, 0, parent,
                             reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), g_inst, nullptr);
    SendMessageW(h, WM_SETFONT, reinterpret_cast<WPARAM>(g_font), TRUE);
    return h;
}

HWND Item(int id) { return GetDlgItem(g_main, id); }
void Move(int id, int x, int y, int w, int h) { MoveWindow(Item(id), x, y, w, h, FALSE); }

// Farbiger Punkt als Symbol (vorberechnet, Alpha-Kante). Kein Icon-Ressourcenfile noetig.
HICON MakeDotIcon(COLORREF c, int size, bool innerDot) {
    BITMAPV5HEADER bi;
    ZeroMemory(&bi, sizeof bi);
    bi.bV5Size = sizeof bi;
    bi.bV5Width = size;
    bi.bV5Height = -size;
    bi.bV5Planes = 1;
    bi.bV5BitCount = 32;
    bi.bV5Compression = BI_BITFIELDS;
    bi.bV5RedMask = 0x00FF0000;
    bi.bV5GreenMask = 0x0000FF00;
    bi.bV5BlueMask = 0x000000FF;
    bi.bV5AlphaMask = 0xFF000000;
    void* bits = nullptr;
    HDC dc = GetDC(nullptr);
    HBITMAP color = CreateDIBSection(dc, reinterpret_cast<BITMAPINFO*>(&bi), DIB_RGB_COLORS, &bits, nullptr, 0);
    ReleaseDC(nullptr, dc);
    if (!color || !bits) return nullptr;
    DWORD* px = static_cast<DWORD*>(bits);
    const float r = static_cast<float>(size) / 2.0f - 0.5f;
    const float inner = r * 0.38f;
    for (int y = 0; y < size; ++y) {
        for (int x = 0; x < size; ++x) {
            const float dx = static_cast<float>(x) - r, dy = static_cast<float>(y) - r;
            const float d = sqrtf(dx * dx + dy * dy);
            float a = r - d + 0.5f;
            a = a < 0.0f ? 0.0f : a > 1.0f ? 1.0f : a;
            float w = innerDot ? inner - d + 0.5f : 0.0f;   // weisser Kern = Tunnel aktiv
            w = w < 0.0f ? 0.0f : w > 1.0f ? 1.0f : w;
            const float cr = (static_cast<float>(GetRValue(c)) * (1 - w) + 255.0f * w) * a;
            const float cg = (static_cast<float>(GetGValue(c)) * (1 - w) + 255.0f * w) * a;
            const float cb = (static_cast<float>(GetBValue(c)) * (1 - w) + 255.0f * w) * a;
            px[y * size + x] = (static_cast<DWORD>(a * 255.0f) << 24) | (static_cast<DWORD>(cr) << 16) |
                               (static_cast<DWORD>(cg) << 8) | static_cast<DWORD>(cb);
        }
    }
    HBITMAP mask = CreateBitmap(size, size, 1, 1, nullptr);
    ICONINFO ii;
    ii.fIcon = TRUE;
    ii.xHotspot = ii.yHotspot = 0;
    ii.hbmMask = mask;
    ii.hbmColor = color;
    HICON icon = CreateIconIndirect(&ii);
    DeleteObject(mask);
    DeleteObject(color);
    return icon;
}

void CreateIcons() {
    const int size = GetSystemMetricsForDpi(SM_CXSMICON, static_cast<UINT>(g_dpi));
    if (size == g_iconDpi) return;
    for (HICON& i : g_icons) if (i) DestroyIcon(i);
    g_icons[0] = MakeDotIcon(RGB(0x8A, 0x8A, 0x8A), size, false);
    g_icons[1] = MakeDotIcon(RGB(0x2E, 0x9E, 0x44), size, true);
    g_icons[2] = MakeDotIcon(RGB(0xE0, 0x8A, 0x00), size, false);
    g_icons[3] = MakeDotIcon(RGB(0xC6, 0x28, 0x28), size, false);
    g_iconDpi = size;
}

// =====================================================================================
// Hilfsfunktionen
// =====================================================================================

void Msg(HWND owner, const wchar_t* text, UINT icon = MB_ICONINFORMATION) {
    MessageBoxW(owner, text, kTitle, MB_OK | icon);
}

bool GetText(HWND h, wchar_t* out, int cap) {
    GetWindowTextW(h, out, cap);
    // Leerzeichen am Rand entfernen
    int n = StrLen(out);
    while (n && (out[n - 1] == L' ' || out[n - 1] == L'\t')) out[--n] = 0;
    int s = 0;
    while (out[s] == L' ' || out[s] == L'\t') ++s;
    if (s) memmove(out, out + s, (static_cast<size_t>(n - s) + 1) * sizeof(wchar_t));
    return out[0] != 0;
}

bool OwnDir(wchar_t* out, size_t cap) {
    const DWORD n = GetModuleFileNameW(nullptr, out, static_cast<DWORD>(cap));
    if (!n || n >= cap) return false;
    wchar_t* slash = wcsrchr(out, L'\\');
    if (!slash) return false;
    slash[1] = 0;
    return true;
}

// wgas.exe: installierte Fassung bevorzugen, sonst die neben wgas-gui.exe.
void WgasExe(wchar_t* out, size_t cap) {
    if (FileExists(g_paths.exe)) { swprintf_s(out, cap, L"%ls", g_paths.exe); return; }
    wchar_t dir[MAX_PATH];
    if (OwnDir(dir, MAX_PATH)) swprintf_s(out, cap, L"%lswgas.exe", dir);
    else swprintf_s(out, cap, L"%ls", g_paths.exe);
}

bool IsElevatedAdmin() {
    BYTE sid[SECURITY_MAX_SID_SIZE];
    DWORD cb = sizeof sid;
    if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, sid, &cb)) return false;
    BOOL member = FALSE;
    return CheckTokenMembership(nullptr, sid, &member) && member;
}

bool ServiceInstalled() {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return false;
    SC_HANDLE svc = OpenServiceW(scm, kSvcName, SERVICE_QUERY_STATUS);
    const bool ok = svc != nullptr;
    if (svc) CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return ok;
}

// ---- Autostart beim Anmelden (HKCU, kein Adminrecht noetig)
bool AutostartEnabled() {
    wchar_t v[MAX_PATH + 32];
    DWORD cb = sizeof v;
    return RegGetValueW(HKEY_CURRENT_USER, kRunKey, kRunValue, RRF_RT_REG_SZ, nullptr, v, &cb) == ERROR_SUCCESS;
}

void SetAutostart(bool on) {
    HKEY k;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, kRunKey, 0, nullptr, 0, KEY_SET_VALUE, nullptr, &k, nullptr) != ERROR_SUCCESS) return;
    if (on) {
        // Installierte Kopie bevorzugen (bleibt nach dem Loeschen des Build-Ordners gueltig).
        wchar_t exe[MAX_PATH], cmd[MAX_PATH + 32];
        if (FileExists(g_paths.guiExe)) StrCopy(exe, MAX_PATH, g_paths.guiExe);
        else GetModuleFileNameW(nullptr, exe, MAX_PATH);
        swprintf_s(cmd, _countof(cmd), L"\"%ls\" --tray", exe);
        RegSetValueExW(k, kRunValue, 0, REG_SZ, reinterpret_cast<const BYTE*>(cmd),
                       static_cast<DWORD>((wcslen(cmd) + 1) * sizeof(wchar_t)));
    } else {
        RegDeleteValueW(k, kRunValue);
    }
    RegCloseKey(k);
}

void FirstRunDefaults() {
    HKEY k;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, kUserKey, 0, nullptr, 0, KEY_READ | KEY_SET_VALUE, nullptr, &k, nullptr) != ERROR_SUCCESS)
        return;
    DWORD v = 0, cb = sizeof v;
    if (RegQueryValueExW(k, L"FirstRunDone", nullptr, nullptr, reinterpret_cast<BYTE*>(&v), &cb) != ERROR_SUCCESS) {
        SetAutostart(true);   // wie WG Tunnel: Tray startet mit der Anmeldung
        v = 1;
        RegSetValueExW(k, L"FirstRunDone", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&v), sizeof v);
    }
    RegCloseKey(k);
}

// ---- Admin-Aktionen per UAC. Ende wird ueber einen Threadpool-Wait gemeldet.
enum class Op { None, Generic, SetConfig, Update };
struct Pending {
    HANDLE process;
    HANDLE wait;
    Op     op;
    wchar_t tmp[MAX_PATH];
};
Pending g_pending[4];

VOID CALLBACK OnElevatedDone(PVOID ctx, BOOLEAN) {
    PostMessageW(g_main, WM_APP_ELEVDONE, reinterpret_cast<WPARAM>(ctx), 0);
}

bool RunElevated(HWND owner, const wchar_t* exe, const wchar_t* params, int show, Op op, const wchar_t* tmp = nullptr) {
    SHELLEXECUTEINFOW sei;
    ZeroMemory(&sei, sizeof sei);
    sei.cbSize = sizeof sei;
    sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI;
    sei.hwnd = owner;
    sei.lpVerb = L"runas";
    sei.lpFile = exe;
    sei.lpParameters = params;
    sei.nShow = show;
    if (!ShellExecuteExW(&sei)) {
        if (GetLastError() != ERROR_CANCELLED) Msg(owner, T(L"Die Aktion konnte nicht mit Adminrechten gestartet werden."), MB_ICONERROR);
        return false;
    }
    if (!sei.hProcess) return true;
    for (Pending& p : g_pending) {
        if (p.process) continue;
        p.process = sei.hProcess;
        p.op = op;
        StrCopy(p.tmp, MAX_PATH, tmp ? tmp : L"");
        if (!RegisterWaitForSingleObject(&p.wait, p.process, OnElevatedDone, &p, INFINITE, WT_EXECUTEONLYONCE))
            p.wait = nullptr;
        return true;
    }
    CloseHandle(sei.hProcess);   // mehr als 4 gleichzeitige Aktionen: Ende nicht verfolgen
    return true;
}

void RunWgasElevated(HWND owner, const wchar_t* params, Op op = Op::Generic, const wchar_t* tmp = nullptr) {
    wchar_t exe[MAX_PATH], full[1024];
    WgasExe(exe, MAX_PATH);
    if (!FileExists(exe)) { Msg(owner, T(L"wgas.exe wurde nicht gefunden (gehört in denselben Ordner wie wgas-gui.exe)."), MB_ICONERROR); return; }
    swprintf_s(full, _countof(full), L"--gui %ls", params);
    RunElevated(owner, exe, full, SW_HIDE, op, tmp);
}

void RunSelfElevated(HWND owner, const wchar_t* params) {
    wchar_t exe[MAX_PATH];
    GetModuleFileNameW(nullptr, exe, MAX_PATH);
    RunElevated(owner, exe, params, SW_SHOWNORMAL, Op::Generic);
}

// =====================================================================================
// Statusabfrage
// =====================================================================================

void ParseStatus(wchar_t* rsp) {
    Model& m = g_m;
    m.nIf = m.nTun = 0;
    m.mode[0] = m.manualTunnel[0] = m.cfgErr[0] = m.target[0] = m.why[0] = 0;
    m.pausedUntil = 0;
    m.cfgValid = m.captive = m.failsafe = false;
    m.conn = 0;
    ResetConfig(m.cfg);

    wchar_t* line = rsp;
    while (*line) {
        wchar_t* end = line;
        while (*end && *end != L'\n') ++end;
        const bool last = *end == 0;
        *end = 0;
        wchar_t* p = line;
        const wchar_t* tag = NextField(p);
        if (StrEq(tag, L"SVC")) {
            StrCopy(m.mode, 16, NextField(p));
            m.pausedUntil = _wcstoui64(NextField(p), nullptr, 10);
            StrCopy(m.manualTunnel, kNameLen, NextField(p));
        } else if (StrEq(tag, L"VER")) {
            StrCopy(m.svcVersion, 16, NextField(p));
        } else if (StrEq(tag, L"CFG")) {
            m.cfgValid = _wtoi(NextField(p)) == 1;
            StrCopy(m.cfgErr, 512, NextField(p));
        } else if (StrEq(tag, L"OPT")) {
            m.cfg.debounceMs = static_cast<unsigned>(_wtoi(NextField(p)));
            m.cfg.noNetworkOn = _wtoi(NextField(p)) == 1;
            m.cfg.captiveWait = _wtoi(NextField(p)) == 1;
            const wchar_t* def = NextField(p);
            if (IsValidTunnelName(def)) m.cfg.defaultTunnel = AddTunnel(m.cfg, def);
        } else if (StrEq(tag, L"TARGET")) {
            StrCopy(m.target, kNameLen, NextField(p));
            m.captive = _wtoi(NextField(p)) == 1;
            m.failsafe = _wtoi(NextField(p)) == 1;
        } else if (StrEq(tag, L"CONN")) {
            m.conn = _wtoi(NextField(p));
        } else if (StrEq(tag, L"WHY")) {
            StrCopy(m.why, 768, NextField(p));
        } else if (StrEq(tag, L"IF") && m.nIf < kMaxIfs) {
            IfInfo& f = m.ifs[m.nIf];
            ZeroBytes(&f, sizeof f);
            f.kind = static_cast<IfKind>(_wtoi(NextField(p)));
            StrCopy(f.alias, kAliasLen, NextField(p));
            f.hasMac = ParseMac(NextField(p), f.gwMac);
            StrCopy(f.dnsSuffix, kDnsLen, NextField(p));
            const wchar_t* ssid = NextField(p);
            if (ssid[0]) { f.hasSsid = true; StrCopy(f.ssid, kSsidLen, ssid); }
            f.hasBssid = ParseMac(NextField(p), f.bssid);
            StrCopy(m.ifRule[m.nIf], kRuleLen, NextField(p));
            ++m.nIf;
        } else if (StrEq(tag, L"TUN") && m.nTun < kMaxKnown) {
            TunInfo& t = m.tun[m.nTun++];
            StrCopy(t.name, kNameLen, NextField(p));
            t.state = _wtoi(NextField(p));
            t.rx = _wcstoui64(NextField(p), nullptr, 10);
            t.tx = _wcstoui64(NextField(p), nullptr, 10);
        } else if (StrEq(tag, L"RULE") && m.cfg.ruleCount < kMaxRules) {
            Rule& r = m.cfg.rules[m.cfg.ruleCount];
            ZeroBytes(&r, sizeof r);
            StrCopy(r.name, kRuleLen, NextField(p));
            const int kind = _wtoi(NextField(p));
            if (kind >= 0) { r.hasKind = true; r.kind = static_cast<IfKind>(kind); }
            const wchar_t* ssid = NextField(p);
            if (ssid[0]) { r.hasSsid = true; StrCopy(r.ssid, kSsidLen, ssid); }
            r.hasBssid = ParseMac(NextField(p), r.bssid);
            r.hasMac = ParseMac(NextField(p), r.gwMac);
            const wchar_t* dns = NextField(p);
            if (dns[0]) { r.hasDns = true; StrCopy(r.dnsSuffix, kDnsLen, dns); }
            const wchar_t* tun = NextField(p);
            r.tunnel = StrIEq(tun, L"none") ? kNoTunnel : AddTunnel(m.cfg, tun);
            if (r.tunnel >= -1) ++m.cfg.ruleCount;
        }
        if (last) break;
        line = end + 1;
    }
}

bool AnyRunning() {
    for (int i = 0; i < g_m.nTun; ++i)
        if (g_m.tun[i].state == static_cast<int>(TState::Running)) return true;
    return false;
}

void UpdateUi();
void UpdateTray(DWORD action);

void Refresh() {
    static wchar_t rsp[kPipeRspChars];
    const DWORD e = PipeTransact(L"status", rsp, kPipeRspChars);
    g_m.connected = e == NO_ERROR;
    g_m.err = e;
    g_m.installed = g_m.connected || ServiceInstalled();
    if (g_m.connected) {
        ParseStatus(rsp);
        if (!g_dirty) g_edit = g_m.cfg;
    }
    if (!g_stateEv) g_stateEv = OpenEventW(SYNCHRONIZE, FALSE, kStateEvent);
    // Dienst nicht erreichbar: alle 30 s neu versuchen (nur dann).
    if (!g_m.connected || !g_stateEv) SetTimer(g_main, TIMER_RECONNECT, 30000, nullptr);
    else KillTimer(g_main, TIMER_RECONNECT);
    UpdateUi();
    UpdateTray(NIM_MODIFY);
}

DWORD SendCommand(const wchar_t* req) {
    wchar_t rsp[512];
    const DWORD e = PipeTransact(req, rsp, _countof(rsp));
    if (e != NO_ERROR) {
        Msg(g_main, T(L"Der Dienst WG-AutoSwitch ist nicht erreichbar."), MB_ICONERROR);
        return e;
    }
    if (StartsWithI(rsp, L"ERR\t")) { Msg(g_main, rsp + 4, MB_ICONERROR); return ERROR_INVALID_FUNCTION; }
    Refresh();
    return NO_ERROR;
}

// =====================================================================================
// Tray
// =====================================================================================

void UpdateTray(DWORD action) {
    CreateIcons();
    int icon = 0;
    wchar_t tip[128];
    if (!g_m.connected) {
        icon = 3;
        swprintf_s(tip, _countof(tip), T(L"%ls – Dienst nicht erreichbar"), kTitle);
    } else {
        const bool running = AnyRunning();
        const bool special = !StrEq(g_m.mode, L"auto") || g_m.captive;
        icon = running ? 1 : special ? 2 : 0;
        const wchar_t* modeText = StrEq(g_m.mode, L"paused") ? T(L" (pausiert)")
                                : StrEq(g_m.mode, L"manual") ? T(L" (manuell)")
                                : g_m.captive ? T(L" (Captive Portal)") : L"";
        swprintf_s(tip, _countof(tip), L"%ls – %ls%ls", kTitle, g_m.target[0] ? g_m.target : T(L"kein Tunnel"), modeText);
    }
    g_nid.uFlags = NIF_ICON | NIF_TIP | NIF_MESSAGE | NIF_SHOWTIP;
    g_nid.hIcon = g_icons[icon];
    StrCopy(g_nid.szTip, _countof(g_nid.szTip), tip);
    if (action == NIM_ADD) {
        Shell_NotifyIconW(NIM_ADD, &g_nid);
        g_nid.uVersion = NOTIFYICON_VERSION_4;
        Shell_NotifyIconW(NIM_SETVERSION, &g_nid);
    } else {
        Shell_NotifyIconW(action, &g_nid);
    }
    SendMessageW(g_main, WM_SETICON, ICON_SMALL, reinterpret_cast<LPARAM>(g_icons[icon]));
}

void ShowMain() {
    ShowWindow(g_main, SW_SHOWNORMAL);
    SetForegroundWindow(g_main);
    Refresh();
    SetTimer(g_main, TIMER_REFRESH, 2000, nullptr);
}

void HideMain() {
    ShowWindow(g_main, SW_HIDE);
    KillTimer(g_main, TIMER_REFRESH);
}

bool AutoUpdateEnabled();

// Offizielle WireGuard-Installation vorhanden? Ohne sie kann der Dienst keine Tunnel schalten.
bool WireGuardInstalled() { return FileExists(g_paths.wgExe); }

// Feste Adresse (kein Wert aus Konfiguration oder Netz) - die Download-Seite bietet ARM64 und x64 an.
void OpenWireGuardDownload() {
    ShellExecuteW(nullptr, L"open", L"https://www.wireguard.com/install/", nullptr, nullptr, SW_SHOWNORMAL);
}

DWORD GetUserDword(const wchar_t* name, DWORD def);
void SetUserDword(const wchar_t* name, DWORD v);

// Beim Start: fehlt WireGuard, darauf hinweisen. Knoepfe "Download-Seite oeffnen" und "OK",
// dazu "Diesen Hinweis nicht mehr anzeigen" (HKCU\Software\WgAutoSwitch\HideWireGuardNotice).
// Tray-Eintrag und Statuszeile bleiben auch dann sichtbar.
void CheckWireGuardOnStart() {
    if (WireGuardInstalled()) {
        // Wieder vorhanden: Abschaltung zuruecksetzen, damit eine spaetere Deinstallation wieder auffaellt.
        if (GetUserDword(L"HideWireGuardNotice", 0)) SetUserDword(L"HideWireGuardNotice", 0);
        return;
    }
    if (GetUserDword(L"HideWireGuardNotice", 0)) return;

    const wchar_t* head = T(L"WireGuard für Windows ist nicht installiert.");
    const wchar_t* body = T(L"WG-AutoSwitch schaltet die Tunnel über die offizielle WireGuard-Installation und kann ohne sie nichts tun. Ihre importierten Tunnel bleiben erhalten.");
    int button = 0;
    BOOL hide = FALSE;

    // TaskDialogIndirect gibt es nur in comctl32 v6; zur Laufzeit holen statt importieren,
    // damit das Programm auch ohne aktives Manifest startet (dann einfache MessageBox).
    using TaskDialogIndirectFn = HRESULT(WINAPI*)(const TASKDIALOGCONFIG*, int*, int*, BOOL*);
    HMODULE cc = GetModuleHandleW(L"comctl32.dll");
    auto tdi = cc ? reinterpret_cast<TaskDialogIndirectFn>(
                        reinterpret_cast<void*>(GetProcAddress(cc, "TaskDialogIndirect"))) : nullptr;
    TASKDIALOG_BUTTON buttons[] = { { IDYES, T(L"Download-Seite öffnen") } };
    TASKDIALOGCONFIG tc;
    ZeroMemory(&tc, sizeof tc);
    tc.cbSize = sizeof tc;
    tc.hwndParent = IsWindowVisible(g_main) ? g_main : nullptr;
    tc.dwFlags = TDF_ALLOW_DIALOG_CANCELLATION;
    tc.dwCommonButtons = TDCBF_OK_BUTTON;
    tc.pszWindowTitle = kTitle;
    tc.pszMainIcon = TD_WARNING_ICON;
    tc.pszMainInstruction = head;
    tc.pszContent = body;
    tc.pButtons = buttons;
    tc.cButtons = _countof(buttons);
    tc.nDefaultButton = IDOK;
    tc.pszVerificationText = T(L"Diesen Hinweis nicht mehr anzeigen");
    if (!tdi || FAILED(tdi(&tc, &button, nullptr, &hide))) {
        wchar_t text[700];
        swprintf_s(text, _countof(text), L"%ls\n\n%ls\n\n%ls", head, body, T(L"Download-Seite von WireGuard jetzt öffnen?"));
        button = MessageBoxW(g_main, text, kTitle, MB_YESNO | MB_ICONWARNING | MB_SETFOREGROUND);
    }
    if (hide) SetUserDword(L"HideWireGuardNotice", 1);
    if (button == IDYES) OpenWireGuardDownload();
}

void TrayMenu() {
    HMENU menu = CreatePopupMenu();
    HMENU pause = CreatePopupMenu();
    if (!WireGuardInstalled()) {
        AppendMenuW(menu, MF_STRING, ID_TRAY_WG_DOWNLOAD, T(L"WireGuard herunterladen …"));
        AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    }
    if (g_m.connected) {
        for (int i = 0; i < g_m.nTun && i < 64; ++i) {
            const TunInfo& t = g_m.tun[i];
            if (t.state == static_cast<int>(TState::Missing)) continue;
            const bool on = t.state == static_cast<int>(TState::Running);
            AppendMenuW(menu, MF_STRING | (on ? MF_CHECKED : 0), ID_TRAY_TUNNEL0 + static_cast<UINT>(i), t.name);
        }
        AppendMenuW(menu, MF_STRING | (AnyRunning() ? 0 : MF_GRAYED), ID_TRAY_DISCONNECT, T(L"Trennen"));
        AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
        if (!StrEq(g_m.mode, L"auto"))
            AppendMenuW(menu, MF_STRING, StrEq(g_m.mode, L"paused") ? ID_TRAY_RESUME : ID_TRAY_AUTO, T(L"Automatik fortsetzen"));
        AppendMenuW(pause, MF_STRING, ID_TRAY_PAUSE15, T(L"15 Minuten"));
        AppendMenuW(pause, MF_STRING, ID_TRAY_PAUSE60, T(L"1 Stunde"));
        AppendMenuW(pause, MF_STRING, ID_TRAY_PAUSE480, T(L"8 Stunden"));
        AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(pause), T(L"Automatik pausieren"));
        AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    } else {
        AppendMenuW(menu, MF_STRING | MF_GRAYED, 0, T(L"Dienst nicht erreichbar"));
        AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
        DestroyMenu(pause);
        pause = nullptr;
    }
    // Sprache: zweisprachig beschriftet, damit man sie auch in der falschen Sprache findet.
    HMENU lang = CreatePopupMenu();
    const wchar_t* ov = LanguageOverride();
    AppendMenuW(lang, MF_STRING | (!ov ? MF_CHECKED : 0), ID_TRAY_LANG_AUTO, T(L"Automatisch (Windows)"));
    AppendMenuW(lang, MF_STRING | (ov && StrIEq(ov, L"de") ? MF_CHECKED : 0), ID_TRAY_LANG_DE, L"Deutsch");
    AppendMenuW(lang, MF_STRING | (ov && StrIEq(ov, L"en") ? MF_CHECKED : 0), ID_TRAY_LANG_EN, L"English");
    AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(lang), CurrentLanguage() == Lang::De ? L"Sprache / Language" : L"Language / Sprache");
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    if (g_upd.available) {
        wchar_t item[96];
        swprintf_s(item, _countof(item), T(L"Update auf %ls installieren …"), g_upd.tag);
        AppendMenuW(menu, MF_STRING | (g_updDownloading ? MF_GRAYED : 0), ID_TRAY_UPDATE_INSTALL, item);
    }
    AppendMenuW(menu, MF_STRING | (g_updChecking ? MF_GRAYED : 0), ID_TRAY_UPDATE_CHECK, T(L"Nach Updates suchen"));
    AppendMenuW(menu, MF_STRING | (AutoUpdateEnabled() ? MF_CHECKED : 0), ID_TRAY_UPDATE_AUTO, T(L"Automatisch nach Updates suchen"));
    AppendMenuW(menu, MF_STRING, ID_TRAY_ABOUT, T(L"Über WG-AutoSwitch …"));
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, ID_TRAY_OPEN, T(L"Öffnen"));
    AppendMenuW(menu, MF_STRING | (AutostartEnabled() ? MF_CHECKED : 0), ID_TRAY_AUTOSTART, T(L"Beim Anmelden starten"));
    AppendMenuW(menu, MF_STRING, ID_TRAY_EXIT, T(L"Beenden"));
    SetMenuDefaultItem(menu, ID_TRAY_OPEN, FALSE);

    POINT pt;
    GetCursorPos(&pt);
    SetForegroundWindow(g_main);
    TrackPopupMenuEx(menu, TPM_RIGHTBUTTON | TPM_BOTTOMALIGN, pt.x, pt.y, g_main, nullptr);
    PostMessageW(g_main, WM_NULL, 0, 0);
    DestroyMenu(menu);   // zerstoert auch das Untermenue
}

// =====================================================================================
// Kleine Formulare (Regel-Editor, Tunnel-Editor): Popup-Fenster mit eigener Nachrichtenschleife
// =====================================================================================

struct Form {
    HWND hwnd;
    bool done;
    bool ok;
    bool (*onOk)(Form&);   // Pruefen/Speichern; false = Fenster bleibt offen
    void* data;
};

LRESULT CALLBACK FormProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    Form* f = reinterpret_cast<Form*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    switch (msg) {
    case WM_NCCREATE:
        SetWindowLongPtrW(hwnd, GWLP_USERDATA,
                          reinterpret_cast<LONG_PTR>(reinterpret_cast<CREATESTRUCTW*>(lp)->lpCreateParams));
        break;
    case WM_COMMAND:
        if (!f) break;
        if (LOWORD(wp) == IDOK) {
            if (f->onOk(*f)) { f->ok = true; f->done = true; }
            return 0;
        }
        if (LOWORD(wp) == IDCANCEL) { f->done = true; return 0; }
        break;
    case WM_CLOSE:
        if (f) f->done = true;
        return 0;
    default:
        break;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

HWND CreateForm(Form& f, HWND owner, const wchar_t* title, int w, int h) {
    RECT rc = { 0, 0, S(w), S(h) };
    AdjustWindowRectExForDpi(&rc, WS_CAPTION | WS_SYSMENU, FALSE, WS_EX_DLGMODALFRAME, static_cast<UINT>(g_dpi));
    int x = CW_USEDEFAULT, y = CW_USEDEFAULT;
    if (owner && IsWindowVisible(owner)) {
        RECT o;
        GetWindowRect(owner, &o);
        x = o.left + ((o.right - o.left) - (rc.right - rc.left)) / 2;
        y = o.top + ((o.bottom - o.top) - (rc.bottom - rc.top)) / 2;
    }
    f.hwnd = CreateWindowExW(WS_EX_DLGMODALFRAME, kFormClass, title, WS_CAPTION | WS_SYSMENU | WS_CLIPCHILDREN, x, y,
                             rc.right - rc.left, rc.bottom - rc.top, owner, nullptr, g_inst, &f);
    return f.hwnd;
}

bool RunForm(Form& f, HWND owner, int firstFocus) {
    if (owner) EnableWindow(owner, FALSE);
    ShowWindow(f.hwnd, SW_SHOW);
    SetFocus(GetDlgItem(f.hwnd, firstFocus));
    MSG msg;
    while (!f.done && GetMessageW(&msg, nullptr, 0, 0) > 0) {
        if (!IsDialogMessageW(f.hwnd, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    if (owner) { EnableWindow(owner, TRUE); SetForegroundWindow(owner); }
    DestroyWindow(f.hwnd);
    return f.ok;
}

// ---- Regel-Editor ------------------------------------------------------------------

struct RuleForm {
    Rule*   rule;
    Config* cfg;
    int     editIndex;   // -1 = neu
};

const IfKind kKinds[4] = { IfKind::Ethernet, IfKind::Wifi, IfKind::Mobile, IfKind::Other };

bool RuleFormOk(Form& f) {
    RuleForm& rf = *static_cast<RuleForm*>(f.data);
    Rule r;
    ZeroBytes(&r, sizeof r);
    wchar_t v[kDnsLen];
    HWND h = f.hwnd;
    if (!GetText(GetDlgItem(h, IDC_F_NAME), v, kRuleLen) || !IsValidRuleName(v)) {
        Msg(h, T(L"Name: 1–47 Zeichen aus A–Z, a–z, 0–9, _ . -"), MB_ICONWARNING);
        return false;
    }
    for (int i = 0; i < rf.cfg->ruleCount; ++i)
        if (i != rf.editIndex && StrIEq(rf.cfg->rules[i].name, v)) {
            Msg(h, T(L"Es gibt bereits eine Regel mit diesem Namen."), MB_ICONWARNING);
            return false;
        }
    StrCopy(r.name, kRuleLen, v);
    const LRESULT type = SendMessageW(GetDlgItem(h, IDC_F_TYPE), CB_GETCURSEL, 0, 0);
    if (type >= 1 && type <= 4) { r.hasKind = true; r.kind = kKinds[type - 1]; }
    if (GetText(GetDlgItem(h, IDC_F_SSID), v, kDnsLen)) {
        const int utf8 = WideCharToMultiByte(CP_UTF8, 0, v, -1, nullptr, 0, nullptr, nullptr);
        if (utf8 - 1 > 32 || wcschr(v, L'"')) { Msg(h, T(L"SSID: höchstens 32 Byte, ohne Anführungszeichen."), MB_ICONWARNING); return false; }
        r.hasSsid = true;
        StrCopy(r.ssid, kSsidLen, v);
    }
    if (GetText(GetDlgItem(h, IDC_F_BSSID), v, kDnsLen)) {
        if (!ParseMac(v, r.bssid) || MacIsZero(r.bssid)) { Msg(h, T(L"BSSID: Format aa:bb:cc:dd:ee:ff"), MB_ICONWARNING); return false; }
        r.hasBssid = true;
    }
    if (GetText(GetDlgItem(h, IDC_F_MAC), v, kDnsLen)) {
        if (!ParseMac(v, r.gwMac) || MacIsZero(r.gwMac)) { Msg(h, T(L"Gateway-MAC: Format aa:bb:cc:dd:ee:ff"), MB_ICONWARNING); return false; }
        r.hasMac = true;
    }
    if (GetText(GetDlgItem(h, IDC_F_DNS), v, kDnsLen)) {
        if (!IsValidDnsSuffix(v)) { Msg(h, T(L"DNS-Suffix: nur A–Z, a–z, 0–9, Punkt und Bindestrich."), MB_ICONWARNING); return false; }
        r.hasDns = true;
        StrCopy(r.dnsSuffix, kDnsLen, v);
    }
    const LRESULT sel = SendMessageW(GetDlgItem(h, IDC_F_TUNNEL), CB_GETCURSEL, 0, 0);
    if (sel <= 0) {
        r.tunnel = kNoTunnel;
    } else {
        wchar_t name[kNameLen];
        SendMessageW(GetDlgItem(h, IDC_F_TUNNEL), CB_GETLBTEXT, static_cast<WPARAM>(sel), reinterpret_cast<LPARAM>(name));
        r.tunnel = AddTunnel(*rf.cfg, name);
        if (r.tunnel < 0) { Msg(h, T(L"Zu viele Tunnel."), MB_ICONWARNING); return false; }
    }
    if (!RuleStrongEnough(r)) {
        Msg(h, r.tunnel == kNoTunnel
                   ? T(L"Ein vertrautes Netz (kein Tunnel) braucht die Gateway-MAC und zusätzlich DNS-Suffix, SSID oder BSSID.\n\nEin WLAN-Name allein kann von jedem nachgeahmt werden.")
                   : T(L"Bitte mindestens ein Merkmal angeben."),
            MB_ICONWARNING);
        return false;
    }
    *rf.rule = r;
    return true;
}

// Bearbeitet r (Vorlage). cfg liefert die Tunnelnamen; neue Namen werden darin ergaenzt.
bool EditRule(HWND owner, Rule& r, Config& cfg, int editIndex) {
    Form f;
    ZeroBytes(&f, sizeof f);
    RuleForm rf = { &r, &cfg, editIndex };
    f.onOk = RuleFormOk;
    f.data = &rf;
    if (!CreateForm(f, owner, editIndex < 0 ? T(L"Neue Regel") : T(L"Regel bearbeiten"), 460, 380)) return false;
    HWND h = f.hwnd;
    struct Row { const wchar_t* label; int id; };
    const Row rows[] = { { T(L"Name:"), IDC_F_NAME }, { T(L"Netztyp:"), IDC_F_TYPE }, { T(L"WLAN-Name (SSID):"), IDC_F_SSID },
                         { T(L"Access Point (BSSID):"), IDC_F_BSSID }, { T(L"Gateway-MAC:"), IDC_F_MAC },
                         { T(L"DNS-Suffix:"), IDC_F_DNS }, { T(L"Tunnel:"), IDC_F_TUNNEL } };
    int y = 12;
    for (const Row& row : rows) {
        HWND lbl = Ctl(h, L"STATIC", row.label, SS_LEFT, -1);
        MoveWindow(lbl, S(12), S(y + 3), S(150), S(20), FALSE);
        HWND c;
        if (row.id == IDC_F_TYPE || row.id == IDC_F_TUNNEL) {
            c = Ctl(h, WC_COMBOBOXW, L"", CBS_DROPDOWNLIST | WS_TABSTOP | WS_VSCROLL, row.id);
            MoveWindow(c, S(166), S(y), S(280), S(200), FALSE);
        } else {
            c = Ctl(h, WC_EDITW, L"", ES_AUTOHSCROLL | WS_TABSTOP, row.id, WS_EX_CLIENTEDGE);
            MoveWindow(c, S(166), S(y), S(280), S(24), FALSE);
        }
        y += 34;
    }
    HWND hint = Ctl(h, L"STATIC",
                    T(L"Alle angegebenen Merkmale müssen passen. «Kein Tunnel» (vertrautes Netz) verlangt die Gateway-MAC plus DNS-Suffix, SSID oder BSSID. Die BSSID bindet an einen einzelnen Access Point."),
                    SS_LEFT, IDC_F_HINT);
    MoveWindow(hint, S(12), S(y), S(434), S(52), FALSE);
    HWND ok = Ctl(h, WC_BUTTONW, L"OK", BS_DEFPUSHBUTTON | WS_TABSTOP, IDOK);
    HWND cancel = Ctl(h, WC_BUTTONW, T(L"Abbrechen"), BS_PUSHBUTTON | WS_TABSTOP, IDCANCEL);
    MoveWindow(ok, S(256), S(340), S(92), S(28), FALSE);
    MoveWindow(cancel, S(354), S(340), S(92), S(28), FALSE);

    // Werte eintragen
    SetWindowTextW(GetDlgItem(h, IDC_F_NAME), r.name);
    HWND type = GetDlgItem(h, IDC_F_TYPE);
    const wchar_t* types[] = { T(L"(beliebig)"), T(L"LAN"), T(L"WLAN"), T(L"Mobilfunk"), T(L"Andere") };
    for (const wchar_t* t : types) SendMessageW(type, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(t));
    int typeSel = 0;
    if (r.hasKind) for (int i = 0; i < 4; ++i) if (kKinds[i] == r.kind) typeSel = i + 1;
    SendMessageW(type, CB_SETCURSEL, static_cast<WPARAM>(typeSel), 0);
    wchar_t mac[24];
    if (r.hasSsid) SetWindowTextW(GetDlgItem(h, IDC_F_SSID), r.ssid);
    if (r.hasBssid) { MacToStr(r.bssid, mac, _countof(mac)); SetWindowTextW(GetDlgItem(h, IDC_F_BSSID), mac); }
    if (r.hasMac) { MacToStr(r.gwMac, mac, _countof(mac)); SetWindowTextW(GetDlgItem(h, IDC_F_MAC), mac); }
    if (r.hasDns) SetWindowTextW(GetDlgItem(h, IDC_F_DNS), r.dnsSuffix);
    HWND tun = GetDlgItem(h, IDC_F_TUNNEL);
    SendMessageW(tun, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(T(L"Kein Tunnel (vertrautes Netz)")));
    int tunSel = 0, idx = 1;
    // Installierte Tunnel + in der Konfiguration genannte
    KnownTunnels names;
    names.n = 0;
    for (int i = 0; i < g_m.nTun; ++i)
        if (g_m.tun[i].state != static_cast<int>(TState::Missing) && names.n < kMaxKnown) StrCopy(names.names[names.n++], kNameLen, g_m.tun[i].name);
    for (int i = 0; i < cfg.tunnelCount; ++i)
        if (FindKnown(names, cfg.tunnels[i]) < 0 && names.n < kMaxKnown) StrCopy(names.names[names.n++], kNameLen, cfg.tunnels[i]);
    for (int i = 0; i < names.n; ++i, ++idx) {
        SendMessageW(tun, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(names.names[i]));
        if (r.tunnel >= 0 && StrIEq(cfg.tunnels[r.tunnel], names.names[i])) tunSel = idx;
    }
    SendMessageW(tun, CB_SETCURSEL, static_cast<WPARAM>(tunSel), 0);
    return RunForm(f, owner, IDC_F_NAME);
}

// ---- Tunnel-Editor (nur im Admin-Prozess) --------------------------------------------

struct TunnelForm {
    bool    isNew;
    bool    fromClipboard;
    wchar_t sourceFile[MAX_PATH];
};

void SecureDelete(const wchar_t* path) {
    HANDLE f = CreateFileW(path, GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (f != INVALID_HANDLE_VALUE) {
        LARGE_INTEGER size;
        if (GetFileSizeEx(f, &size) && size.QuadPart > 0 && size.QuadPart < 1024 * 1024) {
            static const BYTE zero[4096] = {};
            LONGLONG left = size.QuadPart;
            DWORD w = 0;
            while (left > 0) {
                const DWORD chunk = static_cast<DWORD>(left > 4096 ? 4096 : left);
                if (!WriteFile(f, zero, chunk, &w, nullptr)) break;
                left -= chunk;
            }
            FlushFileBuffers(f);
        }
        CloseHandle(f);
    }
    DeleteFileW(path);
}

bool TunnelFormOk(Form& f) {
    TunnelForm& tf = *static_cast<TunnelForm*>(f.data);
    HWND h = f.hwnd;
    wchar_t name[64];
    if (!GetText(GetDlgItem(h, IDC_F_NAME), name, _countof(name)) || !IsValidTunnelName(name)) {
        Msg(h, T(L"Tunnelname: 1–32 Zeichen aus A–Z, a–z, 0–9, _ = + . -"), MB_ICONWARNING);
        return false;
    }
    HWND edit = GetDlgItem(h, IDC_F_TEXT);
    const int len = GetWindowTextLengthW(edit);
    if (len <= 0 || len > 60000) { Msg(h, T(L"Die Konfiguration ist leer oder zu gross."), MB_ICONWARNING); return false; }

    if (tf.isNew) {
        SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        const bool exists = scm && QueryTunnel(scm, name) != TState::Missing;
        if (scm) CloseServiceHandle(scm);
        if (exists && MessageBoxW(h, T(L"Ein Tunnel mit diesem Namen existiert bereits. Ersetzen?"), kTitle,
                                  MB_YESNO | MB_ICONQUESTION) != IDYES)
            return false;
    }

    HANDLE heap = GetProcessHeap();
    wchar_t* text = static_cast<wchar_t*>(HeapAlloc(heap, 0, (static_cast<size_t>(len) + 1) * sizeof(wchar_t)));
    char* utf8 = static_cast<char*>(HeapAlloc(heap, 0, static_cast<size_t>(len) * 3 + 1));
    bool ok = false;
    if (text && utf8) {
        GetWindowTextW(edit, text, len + 1);
        const int bytes = WideCharToMultiByte(CP_UTF8, 0, text, len, utf8, len * 3, nullptr, nullptr);
        // Arbeitskopie im geschuetzten Tunnelordner (nur SYSTEM/Admins), dann importieren.
        wchar_t dir[MAX_PATH], path[MAX_PATH];
        swprintf_s(dir, _countof(dir), L"%ls\\edit", g_paths.tunDir);
        CreateDirectoryW(g_paths.dataDir, nullptr);
        CreateDirectoryW(g_paths.tunDir, nullptr);
        CreateDirectoryW(dir, nullptr);
        ApplySddl(dir, L"O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)");
        swprintf_s(path, _countof(path), L"%ls\\%ls.conf", dir, name);
        HANDLE file = CreateFileW(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        DWORD w = 0;
        const bool wrote = file != INVALID_HANDLE_VALUE && bytes > 0 &&
                           WriteFile(file, utf8, static_cast<DWORD>(bytes), &w, nullptr) && w == static_cast<DWORD>(bytes);
        if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
        SecureZeroMemory(text, (static_cast<size_t>(len) + 1) * sizeof(wchar_t));
        SecureZeroMemory(utf8, static_cast<size_t>(len) * 3 + 1);
        if (wrote) {
            wchar_t exe[MAX_PATH], cmd[MAX_PATH * 2 + 64];
            WgasExe(exe, MAX_PATH);
            swprintf_s(cmd, _countof(cmd), L"\"%ls\" --gui import \"%ls\"", exe, path);
            STARTUPINFOW si;
            ZeroMemory(&si, sizeof si);
            si.cb = sizeof si;
            si.dwFlags = STARTF_USESHOWWINDOW;
            si.wShowWindow = SW_HIDE;
            PROCESS_INFORMATION pi;
            SetCursor(LoadCursorW(nullptr, IDC_WAIT));
            if (CreateProcessW(exe, cmd, nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
                WaitForSingleObject(pi.hProcess, 120000);
                DWORD code = 1;
                GetExitCodeProcess(pi.hProcess, &code);
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
                ok = code == 0;   // Fehlermeldungen zeigt wgas.exe selbst an
            } else {
                Msg(h, T(L"wgas.exe konnte nicht gestartet werden."), MB_ICONERROR);
            }
            SetCursor(LoadCursorW(nullptr, IDC_ARROW));
        } else {
            Msg(h, T(L"Die Arbeitskopie konnte nicht geschrieben werden."), MB_ICONERROR);
        }
        SecureDelete(path);
    }
    if (text) HeapFree(heap, 0, text);
    if (utf8) HeapFree(heap, 0, utf8);
    if (!ok) return false;

    if (tf.fromClipboard && OpenClipboard(h)) {   // privaten Schluessel nicht in der Zwischenablage lassen
        EmptyClipboard();
        CloseClipboard();
    }
    if (tf.sourceFile[0] &&
        MessageBoxW(h, T(L"Tunnel importiert.\n\nDie Quelldatei enthält den privaten Schlüssel. Jetzt löschen?"), kTitle,
                    MB_YESNO | MB_ICONQUESTION) == IDYES)
        SecureDelete(tf.sourceFile);
    return true;
}

// Liest eine Datei (UTF-8 oder ANSI) als Text. Rueckgabe: HeapAlloc-Puffer oder nullptr.
wchar_t* ReadTextFile(const wchar_t* path) {
    HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (f == INVALID_HANDLE_VALUE) return nullptr;
    LARGE_INTEGER size;
    wchar_t* out = nullptr;
    if (GetFileSizeEx(f, &size) && size.QuadPart > 0 && size.QuadPart <= 64 * 1024) {
        HANDLE heap = GetProcessHeap();
        const DWORD n = static_cast<DWORD>(size.QuadPart);
        char* raw = static_cast<char*>(HeapAlloc(heap, 0, n));
        DWORD got = 0;
        if (raw && ReadFile(f, raw, n, &got, nullptr) && got == n) {
            int skip = (n >= 3 && static_cast<unsigned char>(raw[0]) == 0xEF && static_cast<unsigned char>(raw[1]) == 0xBB &&
                        static_cast<unsigned char>(raw[2]) == 0xBF) ? 3 : 0;
            UINT cp = CP_UTF8;
            int wlen = MultiByteToWideChar(cp, MB_ERR_INVALID_CHARS, raw + skip, static_cast<int>(n) - skip, nullptr, 0);
            if (wlen <= 0) { cp = CP_ACP; wlen = MultiByteToWideChar(cp, 0, raw + skip, static_cast<int>(n) - skip, nullptr, 0); }
            if (wlen > 0) {
                out = static_cast<wchar_t*>(HeapAlloc(heap, 0, (static_cast<size_t>(wlen) + 1) * sizeof(wchar_t)));
                if (out) {
                    MultiByteToWideChar(cp, 0, raw + skip, static_cast<int>(n) - skip, out, wlen);
                    out[wlen] = 0;
                }
            }
            SecureZeroMemory(raw, n);
        }
        if (raw) HeapFree(heap, 0, raw);
    }
    CloseHandle(f);
    return out;
}

// Einzelne \n in \r\n wandeln (Edit-Steuerelement braucht CRLF).
wchar_t* ToCrLf(const wchar_t* in) {
    size_t n = 0, lf = 0;
    for (; in[n]; ++n) if (in[n] == L'\n' && (n == 0 || in[n - 1] != L'\r')) ++lf;
    HANDLE heap = GetProcessHeap();
    wchar_t* out = static_cast<wchar_t*>(HeapAlloc(heap, 0, (n + lf + 1) * sizeof(wchar_t)));
    if (!out) return nullptr;
    size_t o = 0;
    for (size_t i = 0; i < n; ++i) {
        if (in[i] == L'\n' && (i == 0 || in[i - 1] != L'\r')) out[o++] = L'\r';
        out[o++] = in[i];
    }
    out[o] = 0;
    return out;
}

// Vorschlag fuer den Tunnelnamen aus einem Dateinamen.
void SuggestName(const wchar_t* path, wchar_t* out) {
    const wchar_t* base = path;
    for (const wchar_t* p = path; *p; ++p) if (*p == L'\\' || *p == L'/') base = p + 1;
    int o = 0;
    for (const wchar_t* p = base; *p && o < kNameLen - 1; ++p) {
        if (*p == L'.' && StrIEq(p, L".conf")) break;
        const wchar_t c = *p;
        const bool ok = (c >= L'a' && c <= L'z') || (c >= L'A' && c <= L'Z') || (c >= L'0' && c <= L'9') ||
                        c == L'_' || c == L'=' || c == L'+' || c == L'.' || c == L'-';
        out[o++] = ok ? c : L'-';
    }
    out[o] = 0;
}

int RunTunnelEditor(const wchar_t* mode, const wchar_t* arg) {
    if (!IsElevatedAdmin()) { Msg(nullptr, T(L"Der Tunnel-Editor braucht Adminrechte."), MB_ICONERROR); return 1; }
    TunnelForm tf;
    ZeroBytes(&tf, sizeof tf);
    wchar_t name[kNameLen] = L"";
    wchar_t* text = nullptr;
    HANDLE heap = GetProcessHeap();

    if (StrEq(mode, L"--edit")) {
        if (!arg || !IsValidTunnelName(arg)) return 2;
        StrCopy(name, kNameLen, arg);
        wchar_t path[MAX_PATH];
        swprintf_s(path, _countof(path), L"%ls\\%ls.conf", g_paths.tunDir, arg);
        text = ReadTextFile(path);
        if (!text) { Msg(nullptr, T(L"Die Konfiguration dieses Tunnels liegt nicht im WG-AutoSwitch-Ordner (nicht über WG-AutoSwitch importiert)."), MB_ICONERROR); return 1; }
    } else if (StrEq(mode, L"--clip")) {
        tf.isNew = tf.fromClipboard = true;
        if (OpenClipboard(nullptr)) {
            HANDLE data = GetClipboardData(CF_UNICODETEXT);
            const wchar_t* src = data ? static_cast<const wchar_t*>(GlobalLock(data)) : nullptr;
            if (src) {
                const size_t n = wcslen(src);
                if (n < 60000) {
                    text = static_cast<wchar_t*>(HeapAlloc(heap, 0, (n + 1) * sizeof(wchar_t)));
                    if (text) StrCopy(text, static_cast<int>(n + 1), src);
                }
                GlobalUnlock(data);
            }
            CloseClipboard();
        }
        if (!text || !wcsstr(text, L"[Interface]")) {
            Msg(nullptr, T(L"Die Zwischenablage enthält keine WireGuard-Konfiguration ([Interface] fehlt).\n\nIn OPNsense: VPN › WireGuard › Peer generator, Konfiguration kopieren."), MB_ICONWARNING);
            if (text) HeapFree(heap, 0, text);
            return 1;
        }
        StrCopy(name, kNameLen, L"wg-");
    } else {   // --new [datei]
        tf.isNew = true;
        if (arg && arg[0]) {
            text = ReadTextFile(arg);
            if (!text) { Msg(nullptr, T(L"Die Datei konnte nicht gelesen werden (leer, zu gross oder kein Zugriff)."), MB_ICONERROR); return 1; }
            StrCopy(tf.sourceFile, MAX_PATH, arg);
            SuggestName(arg, name);
        }
    }
    wchar_t* crlf = text ? ToCrLf(text) : nullptr;
    if (text) { SecureZeroMemory(text, wcslen(text) * sizeof(wchar_t)); HeapFree(heap, 0, text); }

    Form f;
    ZeroBytes(&f, sizeof f);
    f.onOk = TunnelFormOk;
    f.data = &tf;
    CreateFonts();
    wchar_t title[96];
    swprintf_s(title, _countof(title), tf.isNew ? T(L"Tunnel importieren – %ls") : T(L"Tunnel bearbeiten – %ls"), kTitle);
    if (!CreateForm(f, nullptr, title, 620, 560)) return 1;
    HWND h = f.hwnd;
    HWND lbl = Ctl(h, L"STATIC", T(L"Tunnelname:"), SS_LEFT, -1);
    MoveWindow(lbl, S(12), S(15), S(100), S(20), FALSE);
    HWND nameEdit = Ctl(h, WC_EDITW, name, ES_AUTOHSCROLL | WS_TABSTOP | (tf.isNew ? 0 : ES_READONLY), IDC_F_NAME, WS_EX_CLIENTEDGE);
    MoveWindow(nameEdit, S(116), S(12), S(250), S(24), FALSE);
    HWND edit = Ctl(h, WC_EDITW, crlf ? crlf : L"[Interface]\r\nPrivateKey = \r\nAddress = \r\nDNS = \r\n\r\n[Peer]\r\nPublicKey = \r\nAllowedIPs = 0.0.0.0/0, ::/0\r\nEndpoint = \r\n",
                    ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_WANTRETURN | WS_VSCROLL | WS_HSCROLL | WS_TABSTOP,
                    IDC_F_TEXT, WS_EX_CLIENTEDGE);
    SendMessageW(edit, WM_SETFONT, reinterpret_cast<WPARAM>(g_mono), TRUE);
    MoveWindow(edit, S(12), S(46), S(596), S(420), FALSE);
    if (crlf) { SecureZeroMemory(crlf, wcslen(crlf) * sizeof(wchar_t)); HeapFree(heap, 0, crlf); }
    HWND hint = Ctl(h, L"STATIC",
                    T(L"Der Schlüssel wird nur im geschützten Ordner gespeichert (SYSTEM/Administratoren). Für einen Kill-Switch AllowedIPs = 0.0.0.0/0, ::/0 verwenden."),
                    SS_LEFT, IDC_F_HINT);
    MoveWindow(hint, S(12), S(474), S(596), S(36), FALSE);
    HWND ok = Ctl(h, WC_BUTTONW, T(L"Speichern"), BS_DEFPUSHBUTTON | WS_TABSTOP, IDOK);
    HWND cancel = Ctl(h, WC_BUTTONW, T(L"Abbrechen"), BS_PUSHBUTTON | WS_TABSTOP, IDCANCEL);
    MoveWindow(ok, S(418), S(520), S(92), S(28), FALSE);
    MoveWindow(cancel, S(516), S(520), S(92), S(28), FALSE);
    const bool saved = RunForm(f, nullptr, tf.isNew ? IDC_F_NAME : IDC_F_TEXT);
    return saved ? 0 : 1;
}

// =====================================================================================
// Hauptfenster: Inhalt
// =====================================================================================

void SetColumns(HWND lv, const wchar_t* const* titles, const int* widths, int n) {
    while (SendMessageW(lv, LVM_DELETECOLUMN, 0, 0)) {}
    for (int i = 0; i < n; ++i) {
        LVCOLUMNW c;
        ZeroMemory(&c, sizeof c);
        c.mask = LVCF_TEXT | LVCF_WIDTH;
        c.pszText = const_cast<LPWSTR>(titles[i]);
        c.cx = S(widths[i]);
        SendMessageW(lv, LVM_INSERTCOLUMNW, static_cast<WPARAM>(i), reinterpret_cast<LPARAM>(&c));
    }
}

void SetupColumns() {
    static const wchar_t* const tunCols[] = { T(L"Tunnel"), T(L"Status"), T(L"Empfangen"), T(L"Gesendet"), T(L"Verwendung") };
    static const int tunW[] = { 150, 110, 100, 100, 230 };
    SetColumns(Item(IDC_TUNLIST), tunCols, tunW, 5);
    static const wchar_t* const ruleCols[] = { T(L"Regel"), T(L"Typ"), L"SSID", L"BSSID", T(L"Gateway-MAC"), T(L"DNS-Suffix"), T(L"Tunnel") };
    static const int ruleW[] = { 110, 70, 110, 120, 120, 100, 110 };
    SetColumns(Item(IDC_RULES), ruleCols, ruleW, 7);
}

int SelectedIndex(int id) {
    return static_cast<int>(SendMessageW(Item(id), LVM_GETNEXTITEM, static_cast<WPARAM>(-1), LVNI_SELECTED));
}

void SetCell(HWND lv, int row, int col, const wchar_t* text) {
    LVITEMW it;
    ZeroMemory(&it, sizeof it);
    it.iSubItem = col;
    it.pszText = const_cast<LPWSTR>(text);
    SendMessageW(lv, LVM_SETITEMTEXTW, static_cast<WPARAM>(row), reinterpret_cast<LPARAM>(&it));
}

// Fuellt eine Liste; Zeilen werden nur ergaenzt/entfernt, wenn sich die Anzahl aendert (kein Flackern).
void EnsureRows(HWND lv, int n) {
    int have = static_cast<int>(SendMessageW(lv, LVM_GETITEMCOUNT, 0, 0));
    while (have > n) SendMessageW(lv, LVM_DELETEITEM, static_cast<WPARAM>(--have), 0);
    while (have < n) {
        LVITEMW it;
        ZeroMemory(&it, sizeof it);
        it.mask = LVIF_TEXT;
        it.iItem = have++;
        it.pszText = const_cast<LPWSTR>(L"");
        SendMessageW(lv, LVM_INSERTITEMW, 0, reinterpret_cast<LPARAM>(&it));
    }
}

const wchar_t* StateText(int s) {
    switch (static_cast<TState>(s)) {
    case TState::Running:      return T(L"● verbunden");
    case TState::StartPending: return T(L"verbindet …");
    case TState::StopPending:  return T(L"trennt …");
    case TState::Stopped:      return T(L"getrennt");
    case TState::Missing:      return T(L"nicht installiert");
    default:                   return L"?";
    }
}

void FillTunnels() {
    HWND lv = Item(IDC_TUNLIST);
    EnsureRows(lv, g_m.nTun);
    for (int i = 0; i < g_m.nTun; ++i) {
        const TunInfo& t = g_m.tun[i];
        wchar_t rx[32] = L"", tx[32] = L"", use[256] = L"";
        if (t.state == static_cast<int>(TState::Running)) { FormatBytes(t.rx, rx, _countof(rx)); FormatBytes(t.tx, tx, _countof(tx)); }
        const Config& c = g_m.cfg;
        if (c.defaultTunnel >= 0 && StrIEq(c.tunnels[c.defaultTunnel], t.name)) Appendf(use, _countof(use), T(L"Standard (unbekannte Netze)"));
        for (int r = 0; r < c.ruleCount; ++r)
            if (c.rules[r].tunnel >= 0 && StrIEq(c.tunnels[c.rules[r].tunnel], t.name))
                Appendf(use, _countof(use), T(L"%lsRegel %ls"), use[0] ? L", " : L"", c.rules[r].name);
        SetCell(lv, i, 0, t.name);
        SetCell(lv, i, 1, StateText(t.state));
        SetCell(lv, i, 2, rx);
        SetCell(lv, i, 3, tx);
        SetCell(lv, i, 4, use);
    }
}

void FillRules() {
    HWND lv = Item(IDC_RULES);
    EnsureRows(lv, g_edit.ruleCount);
    for (int i = 0; i < g_edit.ruleCount; ++i) {
        const Rule& r = g_edit.rules[i];
        wchar_t mac[24] = L"", bssid[24] = L"";
        if (r.hasMac) MacToStr(r.gwMac, mac, _countof(mac));
        if (r.hasBssid) MacToStr(r.bssid, bssid, _countof(bssid));
        SetCell(lv, i, 0, r.name);
        SetCell(lv, i, 1, r.hasKind ? KindName(r.kind) : T(L"beliebig"));
        SetCell(lv, i, 2, r.hasSsid ? r.ssid : L"");
        SetCell(lv, i, 3, bssid);
        SetCell(lv, i, 4, mac);
        SetCell(lv, i, 5, r.hasDns ? r.dnsSuffix : L"");
        SetCell(lv, i, 6, r.tunnel == kNoTunnel ? T(L"kein Tunnel") : g_edit.tunnels[r.tunnel]);
    }
}

void FillOptions() {
    HWND combo = Item(IDC_DEFAULT);
    SendMessageW(combo, CB_RESETCONTENT, 0, 0);
    int sel = -1, idx = 0;
    const wchar_t* def = g_edit.defaultTunnel >= 0 ? g_edit.tunnels[g_edit.defaultTunnel] : L"";
    bool defListed = false;
    for (int i = 0; i < g_m.nTun; ++i) {
        if (g_m.tun[i].state == static_cast<int>(TState::Missing)) continue;
        SendMessageW(combo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(g_m.tun[i].name));
        if (StrIEq(g_m.tun[i].name, def)) { sel = idx; defListed = true; }
        ++idx;
    }
    if (def[0] && !defListed) {   // in der Konfiguration genannt, aber nicht installiert
        SendMessageW(combo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(def));
        sel = idx;
    }
    SendMessageW(combo, CB_SETCURSEL, static_cast<WPARAM>(sel), 0);
    SendMessageW(Item(IDC_NONET), BM_SETCHECK, g_edit.noNetworkOn ? BST_CHECKED : BST_UNCHECKED, 0);
    SendMessageW(Item(IDC_CAPTIVE), BM_SETCHECK, g_edit.captiveWait ? BST_CHECKED : BST_UNCHECKED, 0);
    wchar_t v[16];
    swprintf_s(v, _countof(v), L"%u", g_edit.debounceMs);
    SetWindowTextW(Item(IDC_DEBOUNCE), v);
}

void UpdateButtons() {
    const int t = SelectedIndex(IDC_TUNLIST);
    const bool conn = g_m.connected;
    const bool sel = t >= 0 && t < g_m.nTun;
    const bool selRunning = sel && g_m.tun[t].state == static_cast<int>(TState::Running);
    EnableWindow(Item(IDC_CONNECT), conn && sel && !selRunning && g_m.tun[t].state != static_cast<int>(TState::Missing));
    EnableWindow(Item(IDC_DISCONNECT), conn && AnyRunning());
    EnableWindow(Item(IDC_AUTO), conn && !StrEq(g_m.mode, L"auto"));
    SetWindowTextW(Item(IDC_AUTO), StrEq(g_m.mode, L"paused") ? T(L"Pause beenden") : T(L"Automatik"));
    EnableWindow(Item(IDC_EDIT), sel);
    EnableWindow(Item(IDC_REMOVE), sel);
    const int r = SelectedIndex(IDC_RULES);
    EnableWindow(Item(IDC_REDIT), r >= 0);
    EnableWindow(Item(IDC_RDEL), r >= 0);
    EnableWindow(Item(IDC_RUP), r > 0);
    EnableWindow(Item(IDC_RDOWN), r >= 0 && r + 1 < g_edit.ruleCount);
    EnableWindow(Item(IDC_TRUST), conn && g_m.nIf > 0);
    EnableWindow(Item(IDC_MAPNET), conn && g_m.nIf > 0);
    EnableWindow(Item(IDC_APPLY), g_dirty);
    SetWindowTextW(Item(IDC_APPLY), g_dirty ? T(L"Übernehmen (Admin) *") : T(L"Übernehmen (Admin)"));
    ShowWindow(Item(IDC_INSTALL), (g_page == 0 && !g_m.installed) ? SW_SHOW : SW_HIDE);
}

void UpdateUi() {
    // Statuszeile (Reiter Tunnel)
    wchar_t s[1200] = L"";
    if (!WireGuardInstalled()) {
        Appendf(s, _countof(s), T(L"WireGuard für Windows fehlt – bitte installieren: https://www.wireguard.com/install/"));
    } else if (!g_m.installed) {
        Appendf(s, _countof(s), T(L"Der Dienst WG-AutoSwitch ist nicht installiert. Ohne Dienst gibt es keine Automatik."));
    } else if (!g_m.connected) {
        Appendf(s, _countof(s), T(L"Dienst nicht erreichbar (gestoppt?). Ereignisanzeige › Anwendung, Quelle WgAutoSwitch."));
    } else {
        Appendf(s, _countof(s), T(L"Aktiv: %ls"), g_m.target[0] ? g_m.target : T(L"kein Tunnel"));
        if (StrEq(g_m.mode, L"paused")) {
            wchar_t t[16];
            FormatLocalTime(g_m.pausedUntil, t, _countof(t));
            Appendf(s, _countof(s), T(L"   ·   Automatik pausiert bis %ls"), t);
        } else if (StrEq(g_m.mode, L"manual")) {
            Appendf(s, _countof(s), T(L"   ·   manuell bis zum nächsten Netzwechsel"));
        } else {
            Appendf(s, _countof(s), T(L"   ·   Automatik aktiv"));
        }
        if (g_m.captive) Appendf(s, _countof(s), T(L"   ·   wartet auf Captive-Portal-Anmeldung"));
        if (g_m.failsafe) Appendf(s, _countof(s), T(L"   ·   Fail-safe"));
        Appendf(s, _countof(s), L"\r\n");
        if (g_m.nIf == 0) Appendf(s, _countof(s), T(L"Kein Netz verbunden. "));
        for (int i = 0; i < g_m.nIf; ++i) {
            if (g_m.ifRule[i][0]) Appendf(s, _countof(s), T(L"%ls \"%ls\": Regel %ls. "), KindName(g_m.ifs[i].kind), g_m.ifs[i].alias, g_m.ifRule[i]);
            else Appendf(s, _countof(s), T(L"%ls \"%ls\": unbekanntes Netz. "), KindName(g_m.ifs[i].kind), g_m.ifs[i].alias);
        }
        Appendf(s, _countof(s), T(L"Konnektivitaet: %ls."), ConnName(static_cast<Connectivity>(g_m.conn)));
    }
    SetWindowTextW(Item(IDC_STATUS), s);

    // Netzinfo (Reiter Auto-Tunneling)
    wchar_t n[2400] = L"";
    if (g_m.connected && !g_m.cfgValid) Appendf(n, _countof(n), T(L"⚠ Konfiguration ungültig: %ls\r\n"), g_m.cfgErr);
    if (g_m.connected && g_m.nIf == 0) Appendf(n, _countof(n), T(L"Kein Netz verbunden.\r\n"));
    for (int i = 0; i < g_m.nIf; ++i) {
        const IfInfo& f = g_m.ifs[i];
        wchar_t mac[24], bssid[24];
        MacToStr(f.gwMac, mac, _countof(mac));
        MacToStr(f.bssid, bssid, _countof(bssid));
        Appendf(n, _countof(n), L"%ls «%ls»", KindName(f.kind), f.alias);
        if (f.kind == IfKind::Wifi) Appendf(n, _countof(n), L"  ·  SSID %ls  ·  BSSID %ls", f.hasSsid ? f.ssid : T(L"(nicht lesbar)"), f.hasBssid ? bssid : L"–");
        Appendf(n, _countof(n), L"  ·  Gateway %ls  ·  DNS %ls\r\n      → %ls%ls\r\n", f.hasMac ? mac : T(L"(nicht ermittelbar)"),
                f.dnsSuffix[0] ? f.dnsSuffix : L"–", g_m.ifRule[i][0] ? T(L"Regel ") : T(L"unbekannt, Standardtunnel"),
                g_m.ifRule[i]);
    }
    if (g_m.connected) Appendf(n, _countof(n), T(L"Konnektivität: %ls"), ConnName(static_cast<Connectivity>(g_m.conn)));
    SetWindowTextW(Item(IDC_NETINFO), n);

    FillTunnels();
    if (!g_dirty) { FillRules(); FillOptions(); }
    UpdateButtons();
}

void ShowPage(int page) {
    g_page = page;
    static const int tunnelIds[] = { IDC_STATUS, IDC_INSTALL, IDC_TUNLIST, IDC_CONNECT, IDC_DISCONNECT, IDC_AUTO,
                                     IDC_IMPORT, IDC_CLIP, IDC_EDIT, IDC_REMOVE };
    static const int autoIds[] = { IDC_NETINFO, IDC_TRUST, IDC_MAPNET, IDC_RULES, IDC_RNEW, IDC_REDIT, IDC_RDEL, IDC_RUP,
                                   IDC_RDOWN, IDC_DEFLBL, IDC_DEFAULT, IDC_NONET, IDC_CAPTIVE, IDC_DEBLBL, IDC_DEBOUNCE, IDC_APPLY };
    for (int id : tunnelIds) ShowWindow(Item(id), page == 0 ? SW_SHOW : SW_HIDE);
    for (int id : autoIds) ShowWindow(Item(id), page == 1 ? SW_SHOW : SW_HIDE);
    if (page == 0) ShowWindow(Item(IDC_INSTALL), g_m.installed ? SW_HIDE : SW_SHOW);
}

void Layout() {
    RECT rc;
    GetClientRect(g_main, &rc);
    const int W = rc.right, H = rc.bottom, m = S(8);
    MoveWindow(g_tab, m, m, W - 2 * m, H - 2 * m, FALSE);
    RECT pg = { 0, 0, W - 2 * m, H - 2 * m };
    TabCtrl_AdjustRect(g_tab, FALSE, &pg);
    const int x = pg.left + m + S(6), y = pg.top + m + S(4), w = pg.right - pg.left - S(12), h = pg.bottom - pg.top - S(10);
    const int bh = S(28), gap = S(6);

    // Reiter Tunnel
    Move(IDC_STATUS, x, y, w - S(170), S(46));
    Move(IDC_INSTALL, x + w - S(160), y, S(160), bh);
    const int listY = y + S(52), btnY = y + h - bh;
    Move(IDC_TUNLIST, x, listY, w, btnY - gap - listY);
    int bx = x;
    const int ids1[] = { IDC_CONNECT, IDC_DISCONNECT, IDC_AUTO };
    for (int id : ids1) { Move(id, bx, btnY, S(100), bh); bx += S(100) + gap; }
    bx = x + w;
    const int ids2[] = { IDC_REMOVE, IDC_EDIT, IDC_CLIP, IDC_IMPORT };
    const int w2[] = { 90, 100, 140, 110 };
    for (int i = 0; i < 4; ++i) { bx -= S(w2[i]); Move(ids2[i], bx, btnY, S(w2[i]), bh); bx -= gap; }

    // Reiter Auto-Tunneling
    const int infoH = S(96);
    Move(IDC_NETINFO, x, y, w - S(200), infoH);
    Move(IDC_TRUST, x + w - S(190), y, S(190), bh);
    Move(IDC_MAPNET, x + w - S(190), y + bh + gap, S(190), bh);
    const int optY = y + h - bh;
    const int rbY = optY - gap - bh;
    Move(IDC_RULES, x, y + infoH + gap, w, rbY - gap - (y + infoH + gap));
    bx = x;
    const int ruleIds[] = { IDC_RNEW, IDC_REDIT, IDC_RDEL, IDC_RUP, IDC_RDOWN };
    const int ruleW[] = { 90, 100, 80, 40, 40 };
    for (int i = 0; i < 5; ++i) { Move(ruleIds[i], bx, rbY, S(ruleW[i]), bh); bx += S(ruleW[i]) + gap; }
    bx = x;
    Move(IDC_DEFLBL, bx, optY + S(5), S(105), S(20)); bx += S(105);
    Move(IDC_DEFAULT, bx, optY + S(1), S(130), S(200)); bx += S(130) + S(12);
    Move(IDC_NONET, bx, optY + S(4), S(150), S(22)); bx += S(150) + S(6);
    Move(IDC_CAPTIVE, bx, optY + S(4), S(150), S(22)); bx += S(150) + S(6);
    Move(IDC_DEBLBL, bx, optY + S(5), S(92), S(20)); bx += S(92);
    Move(IDC_DEBOUNCE, bx, optY + S(1), S(56), S(24));
    Move(IDC_APPLY, x + w - S(170), rbY, S(170), bh);
    InvalidateRect(g_main, nullptr, TRUE);
}

void CreateMainControls() {
    g_tab = Ctl(g_main, WC_TABCONTROLW, L"", WS_CLIPSIBLINGS | WS_TABSTOP, IDC_TAB);
    TCITEMW ti;
    ZeroMemory(&ti, sizeof ti);
    ti.mask = TCIF_TEXT;
    ti.pszText = const_cast<LPWSTR>(T(L"Tunnel"));
    SendMessageW(g_tab, TCM_INSERTITEMW, 0, reinterpret_cast<LPARAM>(&ti));
    ti.pszText = const_cast<LPWSTR>(L"Auto-Tunneling");
    SendMessageW(g_tab, TCM_INSERTITEMW, 1, reinterpret_cast<LPARAM>(&ti));

    const DWORD lvStyle = LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS | WS_TABSTOP;
    Ctl(g_main, L"STATIC", L"", SS_LEFT | SS_NOPREFIX, IDC_STATUS);
    Ctl(g_main, WC_BUTTONW, T(L"Dienst installieren …"), BS_PUSHBUTTON | WS_TABSTOP, IDC_INSTALL);
    HWND lv = Ctl(g_main, WC_LISTVIEWW, L"", lvStyle, IDC_TUNLIST, WS_EX_CLIENTEDGE);
    SendMessageW(lv, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);
    Ctl(g_main, WC_BUTTONW, T(L"Verbinden"), BS_PUSHBUTTON | WS_TABSTOP, IDC_CONNECT);
    Ctl(g_main, WC_BUTTONW, T(L"Trennen"), BS_PUSHBUTTON | WS_TABSTOP, IDC_DISCONNECT);
    Ctl(g_main, WC_BUTTONW, T(L"Automatik"), BS_PUSHBUTTON | WS_TABSTOP, IDC_AUTO);
    Ctl(g_main, WC_BUTTONW, T(L"Importieren …"), BS_PUSHBUTTON | WS_TABSTOP, IDC_IMPORT);
    Ctl(g_main, WC_BUTTONW, T(L"Aus Zwischenablage …"), BS_PUSHBUTTON | WS_TABSTOP, IDC_CLIP);
    Ctl(g_main, WC_BUTTONW, T(L"Bearbeiten …"), BS_PUSHBUTTON | WS_TABSTOP, IDC_EDIT);
    Ctl(g_main, WC_BUTTONW, T(L"Entfernen"), BS_PUSHBUTTON | WS_TABSTOP, IDC_REMOVE);

    Ctl(g_main, L"STATIC", L"", SS_LEFT | SS_NOPREFIX, IDC_NETINFO);
    Ctl(g_main, WC_BUTTONW, T(L"Als vertraut speichern …"), BS_PUSHBUTTON | WS_TABSTOP, IDC_TRUST);
    Ctl(g_main, WC_BUTTONW, T(L"Tunnel zuordnen …"), BS_PUSHBUTTON | WS_TABSTOP, IDC_MAPNET);
    lv = Ctl(g_main, WC_LISTVIEWW, L"", lvStyle, IDC_RULES, WS_EX_CLIENTEDGE);
    SendMessageW(lv, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);
    Ctl(g_main, WC_BUTTONW, T(L"Neu …"), BS_PUSHBUTTON | WS_TABSTOP, IDC_RNEW);
    Ctl(g_main, WC_BUTTONW, T(L"Bearbeiten …"), BS_PUSHBUTTON | WS_TABSTOP, IDC_REDIT);
    Ctl(g_main, WC_BUTTONW, T(L"Löschen"), BS_PUSHBUTTON | WS_TABSTOP, IDC_RDEL);
    Ctl(g_main, WC_BUTTONW, L"▲", BS_PUSHBUTTON | WS_TABSTOP, IDC_RUP);
    Ctl(g_main, WC_BUTTONW, L"▼", BS_PUSHBUTTON | WS_TABSTOP, IDC_RDOWN);
    Ctl(g_main, L"STATIC", T(L"Standardtunnel:"), SS_LEFT, IDC_DEFLBL);
    Ctl(g_main, WC_COMBOBOXW, L"", CBS_DROPDOWNLIST | WS_TABSTOP | WS_VSCROLL, IDC_DEFAULT);
    Ctl(g_main, WC_BUTTONW, T(L"Ohne Netz Tunnel an"), BS_AUTOCHECKBOX | WS_TABSTOP, IDC_NONET);
    Ctl(g_main, WC_BUTTONW, T(L"Captive Portal abwarten"), BS_AUTOCHECKBOX | WS_TABSTOP, IDC_CAPTIVE);
    Ctl(g_main, L"STATIC", T(L"Entprellung ms:"), SS_LEFT, IDC_DEBLBL);
    Ctl(g_main, WC_EDITW, L"", ES_NUMBER | ES_AUTOHSCROLL | WS_TABSTOP, IDC_DEBOUNCE, WS_EX_CLIENTEDGE);
    Ctl(g_main, WC_BUTTONW, T(L"Übernehmen (Admin)"), BS_PUSHBUTTON | WS_TABSTOP, IDC_APPLY);
    SetupColumns();
}

// =====================================================================================
// Hauptfenster: Aktionen
// =====================================================================================

void MarkDirty() {
    g_dirty = true;
    FillRules();
    UpdateButtons();
}

// Vorlage aus der ersten verbundenen Schnittstelle (fuer "Als vertraut speichern" / "Tunnel zuordnen").
Rule RuleFromCurrentNetwork(bool trusted) {
    Rule r;
    ZeroBytes(&r, sizeof r);
    const IfInfo* f = nullptr;
    for (int i = 0; i < g_m.nIf && !f; ++i) if (!g_m.ifRule[i][0]) f = &g_m.ifs[i];   // erstes unbekanntes Netz
    if (!f && g_m.nIf > 0) f = &g_m.ifs[0];
    if (!f) return r;
    // Name: SSID bzw. DNS-Suffix in erlaubte Zeichen umwandeln
    const wchar_t* base = f->hasSsid ? f->ssid : f->dnsSuffix[0] ? f->dnsSuffix : (f->kind == IfKind::Ethernet ? L"lan" : L"netz");
    int o = 0;
    for (const wchar_t* p = base; *p && o < kRuleLen - 1; ++p) {
        const wchar_t c = *p;
        const bool ok = (c >= L'a' && c <= L'z') || (c >= L'A' && c <= L'Z') || (c >= L'0' && c <= L'9') || c == L'_' || c == L'.' || c == L'-';
        r.name[o++] = ok ? c : L'-';
    }
    r.name[o] = 0;
    r.hasKind = true;
    r.kind = f->kind;
    if (f->hasMac) { r.hasMac = true; memcpy(r.gwMac, f->gwMac, 6); }
    if (f->dnsSuffix[0] && IsValidDnsSuffix(f->dnsSuffix)) { r.hasDns = true; StrCopy(r.dnsSuffix, kDnsLen, f->dnsSuffix); }
    if (f->hasSsid) { r.hasSsid = true; StrCopy(r.ssid, kSsidLen, f->ssid); }
    r.tunnel = trusted ? kNoTunnel : g_edit.defaultTunnel;
    return r;
}

void AddRuleDialog(Rule tmpl) {
    if (g_edit.ruleCount >= kMaxRules) { Msg(g_main, T(L"Maximal 32 Regeln."), MB_ICONWARNING); return; }
    Rule r = tmpl;
    if (!EditRule(g_main, r, g_edit, -1)) return;
    g_edit.rules[g_edit.ruleCount++] = r;
    MarkDirty();
    if (MessageBoxW(g_main, T(L"Regel hinzugefügt. Jetzt übernehmen (Adminrechte)?"), kTitle, MB_YESNO | MB_ICONQUESTION) == IDYES)
        SendMessageW(g_main, WM_COMMAND, IDC_APPLY, 0);
}

void ApplyConfig() {
    // Optionen aus den Steuerelementen
    wchar_t v[32];
    GetWindowTextW(Item(IDC_DEBOUNCE), v, _countof(v));
    unsigned ms = 0;
    if (!ParseUInt(v, ms) || ms < 500 || ms > 10000) { Msg(g_main, T(L"Entprellung: 500 bis 10000 ms."), MB_ICONWARNING); return; }
    g_edit.debounceMs = ms;
    g_edit.noNetworkOn = SendMessageW(Item(IDC_NONET), BM_GETCHECK, 0, 0) == BST_CHECKED;
    g_edit.captiveWait = SendMessageW(Item(IDC_CAPTIVE), BM_GETCHECK, 0, 0) == BST_CHECKED;
    const LRESULT sel = SendMessageW(Item(IDC_DEFAULT), CB_GETCURSEL, 0, 0);
    if (sel < 0) { Msg(g_main, T(L"Bitte einen Standardtunnel wählen (zuerst einen Tunnel importieren)."), MB_ICONWARNING); return; }
    wchar_t def[kNameLen];
    SendMessageW(Item(IDC_DEFAULT), CB_GETLBTEXT, static_cast<WPARAM>(sel), reinterpret_cast<LPARAM>(def));
    g_edit.defaultTunnel = AddTunnel(g_edit, def);
    if (g_edit.defaultTunnel < 0) return;

    static wchar_t text[48 * 1024];
    if (!WriteConfigText(g_edit, text, _countof(text))) { Msg(g_main, T(L"Die Konfiguration enthält ungültige Werte."), MB_ICONERROR); return; }
    wchar_t dir[MAX_PATH], tmp[MAX_PATH];
    GetTempPathW(MAX_PATH, dir);
    swprintf_s(tmp, _countof(tmp), L"%lswgas-config-%lu.ini", dir, GetTickCount());
    if (!WriteUtf16File(tmp, text, false)) { Msg(g_main, T(L"Temporäre Datei konnte nicht geschrieben werden."), MB_ICONERROR); return; }
    wchar_t params[MAX_PATH + 32];
    swprintf_s(params, _countof(params), L"setconfig \"%ls\"", tmp);
    RunWgasElevated(g_main, params, Op::SetConfig, tmp);
}

void OnCommand(int id) {
    const int t = SelectedIndex(IDC_TUNLIST);
    const TunInfo* tun = (t >= 0 && t < g_m.nTun) ? &g_m.tun[t] : nullptr;
    wchar_t req[64], params[MAX_PATH + 64];
    switch (id) {
    case IDC_INSTALL:
        RunWgasElevated(g_main, L"install");
        break;
    case IDC_CONNECT:
        if (tun) { swprintf_s(req, _countof(req), L"connect\t%ls", tun->name); SendCommand(req); }
        break;
    case IDC_DISCONNECT:
        SendCommand(L"disconnect");
        break;
    case IDC_AUTO:
        SendCommand(StrEq(g_m.mode, L"paused") ? L"resume" : L"auto");
        break;
    case IDC_IMPORT: {
        wchar_t file[MAX_PATH] = L"";
        OPENFILENAMEW ofn;
        ZeroMemory(&ofn, sizeof ofn);
        ofn.lStructSize = sizeof ofn;
        ofn.hwndOwner = g_main;
        ofn.lpstrFilter = T(L"WireGuard-Konfiguration (*.conf)\0*.conf\0Alle Dateien\0*.*\0");
        ofn.lpstrFile = file;
        ofn.nMaxFile = MAX_PATH;
        ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
        if (GetOpenFileNameW(&ofn)) {
            swprintf_s(params, _countof(params), L"--new \"%ls\"", file);
            RunSelfElevated(g_main, params);
        }
        break;
    }
    case IDC_CLIP:
        RunSelfElevated(g_main, L"--clip");
        break;
    case IDC_EDIT:
        if (tun) { swprintf_s(params, _countof(params), L"--edit %ls", tun->name); RunSelfElevated(g_main, params); }
        break;
    case IDC_REMOVE:
        if (tun) {
            wchar_t q[160];
            swprintf_s(q, _countof(q), T(L"Tunnel «%ls» wirklich entfernen? Die Konfiguration mit dem privaten Schlüssel wird gelöscht."), tun->name);
            if (MessageBoxW(g_main, q, kTitle, MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) == IDYES) {
                swprintf_s(params, _countof(params), L"remove %ls", tun->name);
                RunWgasElevated(g_main, params);
            }
        }
        break;
    case IDC_TRUST:
        AddRuleDialog(RuleFromCurrentNetwork(true));
        break;
    case IDC_MAPNET:
        AddRuleDialog(RuleFromCurrentNetwork(false));
        break;
    case IDC_RNEW: {
        Rule r;
        ZeroBytes(&r, sizeof r);
        r.tunnel = kNoTunnel;
        AddRuleDialog(r);
        break;
    }
    case IDC_REDIT: {
        const int r = SelectedIndex(IDC_RULES);
        if (r < 0) break;
        Rule copy = g_edit.rules[r];
        if (EditRule(g_main, copy, g_edit, r)) { g_edit.rules[r] = copy; MarkDirty(); }
        break;
    }
    case IDC_RDEL: {
        const int r = SelectedIndex(IDC_RULES);
        if (r < 0) break;
        for (int i = r; i + 1 < g_edit.ruleCount; ++i) g_edit.rules[i] = g_edit.rules[i + 1];
        --g_edit.ruleCount;
        MarkDirty();
        break;
    }
    case IDC_RUP:
    case IDC_RDOWN: {
        const int r = SelectedIndex(IDC_RULES);
        const int o = id == IDC_RUP ? r - 1 : r + 1;
        if (r < 0 || o < 0 || o >= g_edit.ruleCount) break;
        const Rule tmp = g_edit.rules[r];
        g_edit.rules[r] = g_edit.rules[o];
        g_edit.rules[o] = tmp;
        MarkDirty();
        LVITEMW it;
        ZeroMemory(&it, sizeof it);
        it.stateMask = it.state = LVIS_SELECTED | LVIS_FOCUSED;
        SendMessageW(Item(IDC_RULES), LVM_SETITEMSTATE, static_cast<WPARAM>(o), reinterpret_cast<LPARAM>(&it));
        UpdateButtons();
        break;
    }
    case IDC_APPLY:
        ApplyConfig();
        break;
    default:
        break;
    }
}

// =====================================================================================
// Version und Updates
// =====================================================================================

DWORD GetUserDword(const wchar_t* name, DWORD def) {
    DWORD v = 0, cb = sizeof v;
    return RegGetValueW(HKEY_CURRENT_USER, kUserKey, name, RRF_RT_REG_DWORD, nullptr, &v, &cb) == ERROR_SUCCESS ? v : def;
}

void SetUserValue(const wchar_t* name, DWORD type, const void* data, DWORD bytes) {
    HKEY k;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, kUserKey, 0, nullptr, 0, KEY_SET_VALUE, nullptr, &k, nullptr) != ERROR_SUCCESS) return;
    RegSetValueExW(k, name, 0, type, static_cast<const BYTE*>(data), bytes);
    RegCloseKey(k);
}

void SetUserDword(const wchar_t* name, DWORD v) { SetUserValue(name, REG_DWORD, &v, sizeof v); }

// Automatische Pruefung: standardmaessig an, im Tray-Menue abschaltbar (siehe PRIVACY.md).
bool AutoUpdateEnabled() { return GetUserDword(L"AutoUpdateCheck", 1) != 0; }

// Datenschutzhinweis zur Update-Pruefung: einmal je Benutzer (SignPath-Bedingung).
void ShowPrivacyNoticeOnce() {
    if (GetUserDword(L"PrivacyNoticeShown", 0)) return;
    SetUserDword(L"PrivacyNoticeShown", 1);
    wchar_t text[900];
    swprintf_s(text, _countof(text),
               T(L"WG-AutoSwitch sucht einmal täglich auf GitHub nach einer neuen Version (api.github.com).\n\nÜbertragen werden dabei nur die üblichen Daten einer HTTPS-Anfrage (IP-Adresse, Programmversion) – keine Netz- oder Konfigurationsdaten. Updates werden erst nach Ihrer Bestätigung installiert.\n\nAbschalten: Tray-Menü › Automatisch nach Updates suchen.\nDatenschutz: https://github.com/%ls/blob/master/PRIVACY.md"),
               WGAS_REPO_WSTR);
    MessageBoxW(g_main, text, kTitle, MB_OK | MB_ICONINFORMATION);
}

void ShowAbout() {
    wchar_t text[600];
    swprintf_s(text, _countof(text),
               T(L"WG-AutoSwitch %ls\nDienst: %ls\n\nSchaltet WireGuard-Tunnel je nach Netz automatisch.\nhttps://github.com/%ls\n\nLizenz: MIT · geschrieben mit Claude (Anthropic)"),
               WGAS_VERSION_WSTR, g_m.svcVersion[0] ? g_m.svcVersion : L"–", WGAS_REPO_WSTR);
    MessageBoxW(g_main, text, kTitle, MB_OK | MB_ICONINFORMATION);
}

void OpenReleasePage() {
    wchar_t url[256];
    if (IsProjectUrl(g_upd.pageUrl)) StrCopy(url, 256, g_upd.pageUrl);
    else swprintf_s(url, _countof(url), L"https://github.com/%ls/releases", WGAS_REPO_WSTR);
    ShellExecuteW(nullptr, L"open", url, nullptr, nullptr, SW_SHOWNORMAL);
}

// Ergebnisse der Hintergrund-Threads; der Hauptthread liest sie erst nach der Meldung.
UpdateInfo g_updTmp;
wchar_t g_updDir[MAX_PATH], g_updMsg[512], g_updSigner[256];

DWORD WINAPI CheckThread(LPVOID manual) {
    const DWORD e = CheckLatest(g_updTmp);
    PostMessageW(g_main, WM_APP_UPDCHECK, reinterpret_cast<WPARAM>(manual), static_cast<LPARAM>(e));
    return 0;
}

DWORD WINAPI DownloadThread(LPVOID) {
    const DWORD e = DownloadUpdate(g_upd, g_updDir, _countof(g_updDir), g_updMsg, _countof(g_updMsg), g_updSigner,
                                   _countof(g_updSigner));
    PostMessageW(g_main, WM_APP_UPDREADY, 0, static_cast<LPARAM>(e));
    return 0;
}

void StartUpdateCheck(bool manual) {
    if (g_updChecking) return;
    g_updChecking = true;
    HANDLE t = CreateThread(nullptr, 0, CheckThread, reinterpret_cast<LPVOID>(static_cast<INT_PTR>(manual ? 1 : 0)), 0, nullptr);
    if (t) CloseHandle(t);
    else g_updChecking = false;
}

void StartUpdateInstall() {
    if (g_updDownloading) return;
    if (!FileExists(g_paths.exe)) {
        Msg(g_main, T(L"Für Updates muss WG-AutoSwitch installiert sein (Dienst installieren)."), MB_ICONWARNING);
        return;
    }
    g_updDownloading = true;
    StrCopy(g_nid.szTip, _countof(g_nid.szTip), T(L"Update wird heruntergeladen …"));
    g_nid.uFlags = NIF_TIP | NIF_SHOWTIP;
    Shell_NotifyIconW(NIM_MODIFY, &g_nid);
    HANDLE t = CreateThread(nullptr, 0, DownloadThread, nullptr, 0, nullptr);
    if (t) CloseHandle(t);
    else g_updDownloading = false;
}

void ShowUpdateDialog() {
    if (!g_upd.available) return;
    wchar_t ver[24], notes[620], text[1600];
    swprintf_s(ver, _countof(ver), L"%u.%u.%u", g_upd.version[0], g_upd.version[1], g_upd.version[2]);
    StrCopy(notes, 600, g_upd.notes);
    if (StrLen(g_upd.notes) > 599) Appendf(notes, _countof(notes), L" …");
    swprintf_s(text, _countof(text),
               T(L"WG-AutoSwitch %ls ist verfügbar (installiert: %ls).\n\n%ls\n\nJa = herunterladen und installieren\nNein = Release-Seite öffnen\nAbbrechen = später"),
               ver, WGAS_VERSION_WSTR, notes);
    const int r = MessageBoxW(g_main, text, kTitle, MB_YESNOCANCEL | MB_ICONINFORMATION | MB_SETFOREGROUND);
    if (r == IDYES) StartUpdateInstall();
    else if (r == IDNO) OpenReleasePage();
}

void OnUpdateChecked(bool manual, DWORD e) {
    g_updChecking = false;
    wchar_t text[400];
    if (e) {
        if (manual) {
            swprintf_s(text, _countof(text), T(L"Die Update-Prüfung ist fehlgeschlagen (Fehler %lu)."), e);
            Msg(g_main, text, MB_ICONWARNING);
        }
        return;
    }
    g_upd = g_updTmp;
    const ULONGLONG now = NowFileTime();
    SetUserValue(L"LastUpdateCheck", REG_QWORD, &now, sizeof now);
    if (!g_upd.available) {
        if (manual) {
            swprintf_s(text, _countof(text), T(L"Sie verwenden die neueste Version (%ls)."), WGAS_VERSION_WSTR);
            Msg(g_main, text);
        }
        return;
    }
    if (manual) { ShowUpdateDialog(); return; }
    // Automatisch: einmal je Version eine Tray-Meldung
    wchar_t notified[32] = L"";
    DWORD cb = sizeof notified;
    RegGetValueW(HKEY_CURRENT_USER, kUserKey, L"NotifiedVersion", RRF_RT_REG_SZ, nullptr, notified, &cb);
    if (StrEq(notified, g_upd.tag)) return;
    SetUserValue(L"NotifiedVersion", REG_SZ, g_upd.tag, static_cast<DWORD>((wcslen(g_upd.tag) + 1) * sizeof(wchar_t)));
    g_nid.uFlags = NIF_INFO;
    g_nid.dwInfoFlags = NIIF_INFO;
    StrCopy(g_nid.szInfoTitle, _countof(g_nid.szInfoTitle), T(L"Update verfügbar"));
    swprintf_s(g_nid.szInfo, _countof(g_nid.szInfo), T(L"WG-AutoSwitch %ls ist verfügbar. Klicken zum Anzeigen."), g_upd.tag);
    Shell_NotifyIconW(NIM_MODIFY, &g_nid);
}

void OnUpdateDownloaded(DWORD e) {
    g_updDownloading = false;
    UpdateTray(NIM_MODIFY);
    wchar_t text[800];
    if (e == kUpdateUnsigned) {
        swprintf_s(text, _countof(text),
                   T(L"Dieses Release ist nicht signiert oder nicht von %ls signiert (gefunden: %ls).\n\nAutomatisch installiert werden nur signierte Releases. Release-Seite öffnen?"),
                   WGAS_PUBLISHER_WSTR, g_updSigner[0] ? g_updSigner : L"–");
        if (MessageBoxW(g_main, text, kTitle, MB_YESNO | MB_ICONWARNING) == IDYES) OpenReleasePage();
        return;
    }
    if (e) {
        wchar_t code[32];
        swprintf_s(code, _countof(code), L"%lu", e);
        swprintf_s(text, _countof(text), T(L"Das Update konnte nicht heruntergeladen oder geprüft werden: %ls"),
                   g_updMsg[0] ? g_updMsg : code);
        Msg(g_main, text, MB_ICONERROR);
        return;
    }
    wchar_t params[MAX_PATH + 32];
    swprintf_s(params, _countof(params), L"update \"%ls\"", g_updDir);
    RunWgasElevated(g_main, params, Op::Update);
}

// Automatische Pruefung: hoechstens alle 20 Stunden; Timer laeuft danach im 24-h-Takt.
void OnUpdateTimer() {
    KillTimer(g_main, TIMER_UPDATE);
    if (AutoUpdateEnabled()) {
        ULONGLONG last = 0;
        DWORD cb = sizeof last;
        RegGetValueW(HKEY_CURRENT_USER, kUserKey, L"LastUpdateCheck", RRF_RT_REG_QWORD, nullptr, &last, &cb);
        const ULONGLONG twentyHours = 20ull * 3600ull * 10000000ull;
        if (NowFileTime() - last >= twentyHours) StartUpdateCheck(false);
    }
    SetTimer(g_main, TIMER_UPDATE, 24u * 3600u * 1000u, nullptr);
}

// Oberflaeche neu starten (nach Sprachwechsel oder Update). exe = nullptr: dieselbe Datei.
void RestartGui(const wchar_t* path) {
    wchar_t exe[MAX_PATH], cmd[MAX_PATH + 8];
    if (path) StrCopy(exe, MAX_PATH, path);
    else GetModuleFileNameW(nullptr, exe, MAX_PATH);
    swprintf_s(cmd, _countof(cmd), L"\"%ls\"", exe);
    if (g_mutex) { CloseHandle(g_mutex); g_mutex = nullptr; }   // neue Instanz darf starten
    STARTUPINFOW si;
    ZeroMemory(&si, sizeof si);
    si.cb = sizeof si;
    PROCESS_INFORMATION pi;
    if (CreateProcessW(exe, cmd, nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    DestroyWindow(g_main);
}

// Sprache speichern und die Oberflaeche auf Wunsch neu starten (Texte werden beim Start gesetzt).
void ChangeLanguage(const wchar_t* code) {
    SetLanguageOverride(code);
    InitLanguage(false);
    if (MessageBoxW(g_main, T(L"Die Sprache wird nach einem Neustart der Oberfläche übernommen. Jetzt neu starten?"),
                    kTitle, MB_YESNO | MB_ICONQUESTION) == IDYES)
        RestartGui(nullptr);
}

void OnTrayCommand(UINT id) {
    wchar_t req[64];
    if (id >= ID_TRAY_TUNNEL0 && id < ID_TRAY_TUNNEL0 + kMaxKnown) {
        const int i = static_cast<int>(id - ID_TRAY_TUNNEL0);
        if (i < g_m.nTun) {
            if (g_m.tun[i].state == static_cast<int>(TState::Running)) SendCommand(L"disconnect");
            else { swprintf_s(req, _countof(req), L"connect\t%ls", g_m.tun[i].name); SendCommand(req); }
        }
        return;
    }
    switch (id) {
    case ID_TRAY_OPEN:       ShowMain(); break;
    case ID_TRAY_DISCONNECT: SendCommand(L"disconnect"); break;
    case ID_TRAY_AUTO:       SendCommand(L"auto"); break;
    case ID_TRAY_RESUME:     SendCommand(L"resume"); break;
    case ID_TRAY_PAUSE15:    SendCommand(L"pause\t15"); break;
    case ID_TRAY_PAUSE60:    SendCommand(L"pause\t60"); break;
    case ID_TRAY_PAUSE480:   SendCommand(L"pause\t480"); break;
    case ID_TRAY_AUTOSTART:  SetAutostart(!AutostartEnabled()); break;
    case ID_TRAY_EXIT:       DestroyWindow(g_main); break;
    case ID_TRAY_LANG_AUTO:  ChangeLanguage(nullptr); break;
    case ID_TRAY_LANG_DE:    ChangeLanguage(L"de"); break;
    case ID_TRAY_LANG_EN:    ChangeLanguage(L"en"); break;
    case ID_TRAY_UPDATE_CHECK:   StartUpdateCheck(true); break;
    case ID_TRAY_UPDATE_AUTO:    SetUserDword(L"AutoUpdateCheck", AutoUpdateEnabled() ? 0 : 1); break;
    case ID_TRAY_UPDATE_INSTALL: ShowUpdateDialog(); break;
    case ID_TRAY_ABOUT:          ShowAbout(); break;
    case ID_TRAY_WG_DOWNLOAD:    OpenWireGuardDownload(); break;
    default: break;
    }
}

LRESULT CALLBACK MainProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    if (msg == g_taskbarCreated && g_taskbarCreated) {   // Explorer neu gestartet
        UpdateTray(NIM_ADD);
        return 0;
    }
    switch (msg) {
    case WM_SIZE:
        if (g_tab) Layout();
        return 0;
    case WM_GETMINMAXINFO: {
        MINMAXINFO* mm = reinterpret_cast<MINMAXINFO*>(lp);
        mm->ptMinTrackSize.x = S(760);
        mm->ptMinTrackSize.y = S(440);
        return 0;
    }
    case WM_DPICHANGED: {
        g_dpi = HIWORD(wp);
        CreateFonts();
        EnumChildWindows(hwnd, SetFontProc, reinterpret_cast<LPARAM>(g_font));
        SetupColumns();
        UpdateUi();
        const RECT* r = reinterpret_cast<const RECT*>(lp);
        SetWindowPos(hwnd, nullptr, r->left, r->top, r->right - r->left, r->bottom - r->top, SWP_NOZORDER | SWP_NOACTIVATE);
        UpdateTray(NIM_MODIFY);
        return 0;
    }
    case WM_COMMAND:
        if (lp == 0 && HIWORD(wp) == 0 && LOWORD(wp) >= ID_TRAY_OPEN) { OnTrayCommand(LOWORD(wp)); return 0; }
        if (HIWORD(wp) == BN_CLICKED) {
            if (LOWORD(wp) == IDC_NONET || LOWORD(wp) == IDC_CAPTIVE) { g_dirty = true; UpdateButtons(); return 0; }
            OnCommand(LOWORD(wp));
            return 0;
        }
        if ((HIWORD(wp) == CBN_SELCHANGE && LOWORD(wp) == IDC_DEFAULT) ||
            (HIWORD(wp) == EN_CHANGE && LOWORD(wp) == IDC_DEBOUNCE && GetFocus() == Item(IDC_DEBOUNCE))) {
            g_dirty = true;
            UpdateButtons();
        }
        return 0;
    case WM_NOTIFY: {
        const NMHDR* nm = reinterpret_cast<const NMHDR*>(lp);
        if (nm->idFrom == IDC_TAB && nm->code == TCN_SELCHANGE) {
            ShowPage(static_cast<int>(SendMessageW(g_tab, TCM_GETCURSEL, 0, 0)));
        } else if (nm->code == LVN_ITEMCHANGED) {
            UpdateButtons();
        } else if (nm->code == NM_DBLCLK) {
            if (nm->idFrom == IDC_TUNLIST) {
                const int t = SelectedIndex(IDC_TUNLIST);
                if (t >= 0 && t < g_m.nTun) OnCommand(g_m.tun[t].state == static_cast<int>(TState::Running) ? IDC_DISCONNECT : IDC_CONNECT);
            } else if (nm->idFrom == IDC_RULES) {
                OnCommand(IDC_REDIT);
            }
        }
        return 0;
    }
    case WM_TIMER:
        if (wp == TIMER_REFRESH || wp == TIMER_RECONNECT) Refresh();
        else if (wp == TIMER_UPDATE) OnUpdateTimer();
        return 0;
    case WM_APP_UPDCHECK:
        OnUpdateChecked(wp != 0, static_cast<DWORD>(lp));
        return 0;
    case WM_APP_UPDREADY:
        OnUpdateDownloaded(static_cast<DWORD>(lp));
        return 0;
    case WM_APP_TRAY:
        switch (LOWORD(lp)) {
        case kNinBalloonUserClick:
            ShowUpdateDialog();
            break;
        case NIN_SELECT:
        case NIN_KEYSELECT:
            if (IsWindowVisible(hwnd)) HideMain(); else ShowMain();
            break;
        case WM_CONTEXTMENU:
            Refresh();
            TrayMenu();
            break;
        default:
            break;
        }
        return 0;
    case WM_APP_SHOW:
        ShowMain();
        return 0;
    case WM_APP_ELEVDONE: {
        Pending* p = reinterpret_cast<Pending*>(wp);
        if (p && p->process) {
            DWORD code = 1;
            GetExitCodeProcess(p->process, &code);
            if (p->wait) UnregisterWait(p->wait);
            CloseHandle(p->process);
            const bool updated = p->op == Op::Update && code == 0;
            if (p->op == Op::SetConfig) {
                if (code == 0) g_dirty = false;
                if (p->tmp[0]) DeleteFileW(p->tmp);   // falls wgas.exe sie nicht schon geloescht hat
            }
            ZeroBytes(p, sizeof *p);
            if (updated) {   // neue Oberflaeche aus dem Programmordner starten
                RestartGui(g_paths.guiExe);
                return 0;
            }
        }
        Refresh();
        return 0;
    }
    case WM_CLOSE:   // Schliessen = in den Tray
        HideMain();
        return 0;
    case WM_DESTROY:
        Shell_NotifyIconW(NIM_DELETE, &g_nid);
        PostQuitMessage(0);
        return 0;
    default:
        break;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

bool RegisterClasses() {
    WNDCLASSEXW wc;
    ZeroMemory(&wc, sizeof wc);
    wc.cbSize = sizeof wc;
    wc.lpfnWndProc = MainProc;
    wc.hInstance = g_inst;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = GetSysColorBrush(COLOR_BTNFACE);   // wie Standarddialoge: Beschriftungen ohne Kanten
    wc.lpszClassName = kMainClass;
    if (!RegisterClassExW(&wc)) return false;
    wc.lpfnWndProc = FormProc;
    wc.lpszClassName = kFormClass;
    wc.hbrBackground = GetSysColorBrush(COLOR_BTNFACE);   // wie Standarddialoge: Beschriftungen ohne Kanten
    return RegisterClassExW(&wc) != 0;
}

int RunMain(bool startHidden) {
    // Nur eine Instanz je Benutzer; zweiter Start holt das Fenster nach vorn.
    g_mutex = CreateMutexW(nullptr, TRUE, L"Local\\WgAutoSwitchGui");
    if (g_mutex && GetLastError() == ERROR_ALREADY_EXISTS) {
        HWND other = FindWindowW(kMainClass, nullptr);
        if (other && !startHidden) PostMessageW(other, WM_APP_SHOW, 0, 0);
        CloseHandle(g_mutex);
        return 0;
    }
    FirstRunDefaults();
    if (AutostartEnabled()) SetAutostart(true);   // Pfad aktualisieren (z. B. nach "Dienst installieren")

    wchar_t title[64];
    swprintf_s(title, _countof(title), L"%ls %ls", kTitle, WGAS_VERSION_WSTR);
    g_main = CreateWindowExW(0, kMainClass, title, WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN, CW_USEDEFAULT, CW_USEDEFAULT,
                             100, 100, nullptr, nullptr, g_inst, nullptr);
    if (!g_main) return 1;
    g_dpi = static_cast<int>(GetDpiForWindow(g_main));
    CreateFonts();
    CreateMainControls();
    SetWindowPos(g_main, nullptr, 0, 0, S(900), S(560), SWP_NOMOVE | SWP_NOZORDER);
    Layout();
    ShowPage(0);

    g_taskbarCreated = RegisterWindowMessageW(L"TaskbarCreated");
    ZeroMemory(&g_nid, sizeof g_nid);
    g_nid.cbSize = sizeof g_nid;
    g_nid.hWnd = g_main;
    g_nid.uID = 1;
    g_nid.uCallbackMessage = WM_APP_TRAY;
    Refresh();
    UpdateTray(NIM_ADD);
    if (!startHidden) ShowMain();
    CheckWireGuardOnStart();
    ShowPrivacyNoticeOnce();
    SetTimer(g_main, TIMER_UPDATE, 60u * 1000u, nullptr);   // erste automatische Pruefung nach 1 Minute

    // Nachrichtenschleife: wartet zusaetzlich auf das Zustandssignal des Dienstes.
    MSG msg;
    for (;;) {
        const DWORD n = g_stateEv ? 1 : 0;
        const DWORD r = MsgWaitForMultipleObjectsEx(n, &g_stateEv, INFINITE, QS_ALLINPUT, MWMO_INPUTAVAILABLE);
        if (n && r == WAIT_OBJECT_0) { Refresh(); continue; }
        if (r == WAIT_FAILED) { CloseHandle(g_stateEv); g_stateEv = nullptr; Sleep(100); }
        while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
            if (msg.message == WM_QUIT) {
                if (g_stateEv) CloseHandle(g_stateEv);
                if (g_mutex) CloseHandle(g_mutex);
                return static_cast<int>(msg.wParam);
            }
            if (!IsDialogMessageW(g_main, &msg)) {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
    }
}

} // namespace

int WINAPI wWinMain(HINSTANCE inst, HINSTANCE, LPWSTR, int) {
    g_inst = inst;
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    INITCOMMONCONTROLSEX icc;
    icc.dwSize = sizeof icc;
    icc.dwICC = ICC_LISTVIEW_CLASSES | ICC_TAB_CLASSES | ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icc);
    if (!InitPaths(g_paths) || !RegisterClasses()) return 1;
    InitLanguage(false);

    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    int rc = 0;
    if (argv && argc >= 2 && (StrEq(argv[1], L"--edit") || StrEq(argv[1], L"--new") || StrEq(argv[1], L"--clip"))) {
        g_dpi = static_cast<int>(GetDpiForSystem());
        rc = RunTunnelEditor(argv[1], argc >= 3 ? argv[2] : nullptr);
    } else {
        rc = RunMain(argv && argc >= 2 && StrEq(argv[1], L"--tray"));
    }
    if (argv) LocalFree(argv);
    return rc;
}
