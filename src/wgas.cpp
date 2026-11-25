// wgas.cpp - WG-AutoSwitch: Dienst und Kommandozeile.
// Ziel: Windows 11 ARM64 (Snapdragon / Surface), laeuft ebenso auf x64.
//
//   wgas.exe service             -> vom Dienststeuerungs-Manager (SCM) gestartet
//   wgas.exe <befehl>            -> CLI (siehe Usage)
//   wgas.exe --gui <befehl>      -> von wgas-gui.exe per UAC gestartet: keine Konsole,
//                                   Fehler und Warnungen erscheinen als Meldungsfenster
//
// Energie: Der Dienst-Thread blockiert in WaitForMultipleObjects OHNE Timeout. Geweckt wird
// er nur durch Windows-Benachrichtigungen (IP-Schnittstellen, IP-Adressen, Konnektivitaet,
// Energie), durch Anfragen ueber die Named Pipe oder durch einmalige Timer, die erst nach
// einem Ereignis gesetzt werden (Entprellung, Wiederholung, Pausenende, Pipe-Zeitlimit).
//
// Sicherheit: Der Dienst laeuft als virtuelles Konto "NT SERVICE\WgAutoSwitch" und darf auf den
// Tunnel-Diensten WireGuardTunnel$<name> nur Start/Stop/Status. Die Named Pipe ist lokal
// (PIPE_REJECT_REMOTE_CLIENTS, Netzwerkanmeldungen verweigert) und nur fuer SYSTEM,
// Administratoren und interaktiv angemeldete Benutzer offen. Benutzer duerfen den Status lesen,
// verbinden, trennen und pausieren - Konfiguration und Schluessel aendern nur Administratoren.

#include "common.h"
#include <io.h>
#include <fcntl.h>
#include <conio.h>
#include <stdlib.h>

#include "wgas_msg.h"   // von mc.exe aus wgas_msg.mc erzeugt: MSG_INFO, MSG_WARNING, MSG_ERROR

#pragma comment(lib, "user32.lib")

using namespace wgas;

namespace {

// =====================================================================================
// Konstanten und globaler Zustand
// =====================================================================================

constexpr wchar_t kSvcDescription[] =
    L"Schaltet WireGuard-Tunnel je nach verbundenem Netz automatisch ein oder aus.";
constexpr wchar_t kEvtKey[] = L"SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\WgAutoSwitch";
constexpr DWORD    kCtrlReload   = 128;                          // benutzerdefinierter Steuercode
constexpr LONGLONG kRetryMs[3]   = { 30000, 120000, 600000 };    // Backoff: 30 s, 2 min, 10 min
constexpr LONGLONG kPipeIdleMs   = 5000;                         // Zeitlimit je Pipe-Verbindung
constexpr DWORD    kMaxConfBytes = 64 * 1024;

Config       g_cfg;
Snapshot     g_snap;
KnownTunnels g_known;

SERVICE_STATUS_HANDLE g_ssh;
SERVICE_STATUS        g_ss;
HANDLE g_evStop, g_evNet, g_evReload, g_tmDebounce, g_tmRetry, g_tmPause, g_tmPipe, g_evPipe;
HANDLE g_stateEvent;   // "Global\WgAutoSwitchState": weckt wgas-gui.exe bei Zustandswechseln

// Ausgabe: Konsole, oder im --gui-Modus Sammelpuffer fuer ein Meldungsfenster.
bool    g_guiMode;
wchar_t g_guiOut[8192];

void OutV(FILE* stream, const wchar_t* fmt, va_list ap) {
    if (g_guiMode) {
        const size_t used = wcslen(g_guiOut);
        if (used + 1 < _countof(g_guiOut))
            _vsnwprintf_s(g_guiOut + used, _countof(g_guiOut) - used, _TRUNCATE, fmt, ap);
    } else {
        vfwprintf(stream, fmt, ap);
    }
}
void Out(const wchar_t* fmt, ...) { va_list ap; va_start(ap, fmt); OutV(stdout, fmt, ap); va_end(ap); }
void Err(const wchar_t* fmt, ...) { va_list ap; va_start(ap, fmt); OutV(stderr, fmt, ap); va_end(ap); }

void Log(WORD type, const wchar_t* fmt, ...) {
    wchar_t msg[1024];
    va_list ap;
    va_start(ap, fmt);
    _vsnwprintf_s(msg, _countof(msg), _TRUNCATE, fmt, ap);
    va_end(ap);
    const DWORD id = type == EVENTLOG_ERROR_TYPE ? MSG_ERROR : type == EVENTLOG_WARNING_TYPE ? MSG_WARNING : MSG_INFO;
    HANDLE h = RegisterEventSourceW(nullptr, kSvcName);
    if (!h) return;
    LPCWSTR strs[1] = { msg };
    ReportEventW(h, type, 0, id, nullptr, 1, 0, strs, nullptr);
    DeregisterEventSource(h);
}

void PrintError(const wchar_t* what, DWORD err) {
    wchar_t sys[256] = L"";
    FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, err, 0, sys,
                   static_cast<DWORD>(_countof(sys)), nullptr);
    for (wchar_t* p = sys; *p; ++p) if (*p == L'\r' || *p == L'\n') *p = L' ';
    Err(L"Fehler: %ls (%lu: %ls)\n", what, err, sys);
}

// =====================================================================================
// Dienst: Zustand und Tunnelsteuerung
// =====================================================================================

struct SvcState {
    bool      cfgValid;
    wchar_t   cfgErr[512];
    ULONGLONG pausedUntil;               // 0 = keine Pause
    bool      captiveLogged;
    int       retryStage;
    bool      manual;                    // Benutzer hat manuell geschaltet
    wchar_t   manualTunnel[kNameLen];    // "" = manuell getrennt
    unsigned long long manualFp;         // gilt bis sich dieses Netz aendert
    // zuletzt bewertet (fuer "status")
    unsigned long long lastFp;
    Connectivity lastConn;
    Decision     lastDecision;
    wchar_t      lastTarget[kNameLen];
    wchar_t      lastWhy[768];
};
SvcState g_st;

void SetSvcStatus(DWORD state, DWORD exitCode = NO_ERROR, DWORD waitHint = 0) {
    static DWORD checkpoint = 1;
    g_ss.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ss.dwCurrentState = state;
    g_ss.dwWin32ExitCode = exitCode;
    g_ss.dwWaitHint = waitHint;
    g_ss.dwControlsAccepted = state == SERVICE_RUNNING
        ? (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_POWEREVENT) : 0;
    g_ss.dwCheckPoint = (state == SERVICE_RUNNING || state == SERVICE_STOPPED) ? 0 : checkpoint++;
    SetServiceStatus(g_ssh, &g_ss);
}

// Einmaliger relativer Timer; 500 ms Toleranz erlauben Windows das Buendeln von Weckungen.
void ArmTimer(HANDLE t, LONGLONG ms) {
    LARGE_INTEGER due;
    due.QuadPart = -ms * 10000LL;
    SetWaitableTimerEx(t, &due, 0, nullptr, nullptr, nullptr, 500);
}

void PulseState() {
    if (g_stateEvent) PulseEvent(g_stateEvent);
}

void EnterLowPowerMode() {
    PROCESS_POWER_THROTTLING_STATE p;
    ZeroMemory(&p, sizeof p);
    p.Version = PROCESS_POWER_THROTTLING_CURRENT_VERSION;
    p.ControlMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED;   // EcoQoS
#ifdef PROCESS_POWER_THROTTLING_IGNORE_TIMER_RESOLUTION
    p.ControlMask |= PROCESS_POWER_THROTTLING_IGNORE_TIMER_RESOLUTION;
#endif
    p.StateMask = p.ControlMask;
    SetProcessInformation(GetCurrentProcess(), ProcessPowerThrottling, &p, sizeof p);
    SetPriorityClass(GetCurrentProcess(), PROCESS_MODE_BACKGROUND_BEGIN);
}

// Setzt den Soll-Zustand: hoechstens ein Tunnel aktiv. Protokolliert nur echte Wechsel (F9).
// want == nullptr oder "" -> alle Tunnel aus.
DWORD ApplyTunnel(const wchar_t* want, const wchar_t* why) {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) return GetLastError();
    EnumTunnels(scm, &g_cfg, g_known);
    const bool wantAny = want && want[0];
    for (int i = 0; i < g_known.n; ++i) {
        if (wantAny && StrIEq(g_known.names[i], want)) continue;
        const TState s = QueryTunnel(scm, g_known.names[i]);
        if (s == TState::Running || s == TState::StartPending) {
            const DWORD e = StopTunnel(scm, g_known.names[i]);
            if (e == NO_ERROR) Log(EVENTLOG_INFORMATION_TYPE, L"Tunnel \"%ls\" ausgeschaltet. %ls", g_known.names[i], why);
            else Log(EVENTLOG_WARNING_TYPE, L"Tunnel \"%ls\" liess sich nicht stoppen (Fehler %lu).", g_known.names[i], e);
        }
    }
    DWORD err = NO_ERROR;
    if (wantAny) {
        const TState s = QueryTunnel(scm, want);
        if (s == TState::Missing) err = ERROR_SERVICE_DOES_NOT_EXIST;
        else if (s == TState::Error) err = ERROR_ACCESS_DENIED;
        else if (s != TState::Running && s != TState::StartPending) {
            err = StartTunnel(scm, want);
            if (err == NO_ERROR) Log(EVENTLOG_INFORMATION_TYPE, L"Tunnel \"%ls\" eingeschaltet. %ls", want, why);
        }
    }
    CloseServiceHandle(scm);
    return err;
}

void Describe(const Config& c, const Snapshot& s, Connectivity conn, wchar_t* out, size_t cap) {
    out[0] = 0;
    if (!s.ok) Appendf(out, cap, L"Netzwerkzustand nicht lesbar. ");
    else if (s.n == 0) Appendf(out, cap, L"Kein Netz verbunden. ");
    for (int i = 0; i < s.n; ++i) {
        const int r = MatchRule(c, s.ifs[i]);
        if (r >= 0) Appendf(out, cap, L"%ls \"%ls\": Regel %ls. ", KindName(s.ifs[i].kind), s.ifs[i].alias, c.rules[r].name);
        else        Appendf(out, cap, L"%ls \"%ls\": unbekanntes Netz. ", KindName(s.ifs[i].kind), s.ifs[i].alias);
    }
    Appendf(out, cap, L"Konnektivitaet: %ls.", ConnName(conn));
}

void Evaluate(SvcState& st, bool fromRetry) {
    if (!fromRetry) {
        st.retryStage = 0;
        CancelWaitableTimer(g_tmRetry);
    }
    const bool ok = CollectInterfaces(&g_cfg, g_snap);
    const Connectivity conn = QueryConnectivity();
    const Decision d = Decide(g_cfg, g_snap.ifs, ok ? g_snap.n : 0, conn, ok && st.cfgValid);
    const unsigned long long fp = NetFingerprint(g_snap.ifs, ok ? g_snap.n : 0);
    st.lastFp = fp;
    st.lastConn = conn;
    st.lastDecision = d;
    Describe(g_cfg, g_snap, conn, st.lastWhy, _countof(st.lastWhy));

    // Manuelle Wahl gilt bis zum naechsten echten Netzwechsel.
    if (st.manual && fp != st.manualFp) {
        st.manual = false;
        Log(EVENTLOG_INFORMATION_TYPE, L"Netzwechsel: manuelle Wahl aufgehoben, Automatik entscheidet wieder.");
    }
    const wchar_t* target = st.manual ? st.manualTunnel
                          : (d.tunnel >= 0 ? g_cfg.tunnels[d.tunnel] : L"");
    StrCopy(st.lastTarget, kNameLen, target);

    if (!st.manual && d.captiveHold) {
        if (!st.captiveLogged) {
            Log(EVENTLOG_WARNING_TYPE, L"Captive Portal erkannt: Tunnel wartet, bis Internetzugang besteht. %ls", st.lastWhy);
            st.captiveLogged = true;
        }
    } else {
        st.captiveLogged = false;
    }

    const DWORD err = ApplyTunnel(target, st.manual ? L"(manuell)" : st.lastWhy);
    PulseState();
    if (err == NO_ERROR) { st.retryStage = 0; return; }
    if (st.retryStage < 3) {
        if (st.retryStage == 0)
            Log(EVENTLOG_ERROR_TYPE, L"Tunnel \"%ls\" konnte nicht gestartet werden (Fehler %lu). Neue Versuche nach 30 s, 2 min, 10 min. %ls",
                target, err, st.lastWhy);
        ArmTimer(g_tmRetry, kRetryMs[st.retryStage]);
        ++st.retryStage;
    } else {
        Log(EVENTLOG_ERROR_TYPE, L"Tunnel \"%ls\" weiterhin nicht startbar (Fehler %lu). Naechster Versuch beim naechsten Netzwechsel.",
            target, err);
    }
}

void LoadState(SvcState& st) {
    st.cfgErr[0] = 0;
    const bool ok = ConfigIsSecure(g_paths, st.cfgErr, _countof(st.cfgErr)) &&
                    LoadConfig(g_paths.cfg, g_cfg, st.cfgErr, _countof(st.cfgErr));
    if (!ok) {
        BuildFailsafeConfig(g_cfg);
        Log(EVENTLOG_ERROR_TYPE, L"Konfiguration nicht verwendbar: %ls Fail-safe: Tunnel \"%ls\" bleibt an.",
            st.cfgErr, TunnelLabel(g_cfg, g_cfg.defaultTunnel));
    }
    st.cfgValid = ok;
}

void SetPause(SvcState& st, unsigned minutes) {
    if (minutes == 0) {
        CancelWaitableTimer(g_tmPause);
        if (st.pausedUntil) Log(EVENTLOG_INFORMATION_TYPE, L"Pause aufgehoben.");
        st.pausedUntil = 0;
        return;
    }
    st.pausedUntil = NowFileTime() + static_cast<ULONGLONG>(minutes) * 60ull * 10000000ull;
    LARGE_INTEGER due;
    due.QuadPart = static_cast<LONGLONG>(st.pausedUntil);   // positiv = absolute UTC-Zeit
    SetWaitableTimerEx(g_tmPause, &due, 0, nullptr, nullptr, nullptr, 1000);
    CancelWaitableTimer(g_tmDebounce);
    CancelWaitableTimer(g_tmRetry);
    wchar_t t[16];
    FormatLocalTime(st.pausedUntil, t, _countof(t));
    Log(EVENTLOG_INFORMATION_TYPE, L"Automatik pausiert bis %ls.", t);
}

// =====================================================================================
// Dienst: Named Pipe (ein Thread, Overlapped-I/O im selben Warteaufruf)
// =====================================================================================

enum class PipeState { Off, Listening, Reading, Writing };
struct PipeSrv {
    HANDLE     h;
    OVERLAPPED ov;
    PipeState  state;
    wchar_t    req[kPipeReqChars];
    wchar_t    rsp[kPipeRspChars];
};
PipeSrv g_pipe;

bool CreateSa(const wchar_t* sddl, SECURITY_ATTRIBUTES& sa) {
    ZeroMemory(&sa, sizeof sa);
    sa.nLength = sizeof sa;
    return ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &sa.lpSecurityDescriptor, nullptr) != FALSE;
}

void PipeListen();

void PipeReset() {
    CancelWaitableTimer(g_tmPipe);
    if (g_pipe.h == INVALID_HANDLE_VALUE) return;
    DisconnectNamedPipe(g_pipe.h);
    PipeListen();
}

void PipeListen() {
    ZeroMemory(&g_pipe.ov, sizeof g_pipe.ov);
    g_pipe.ov.hEvent = g_evPipe;
    ResetEvent(g_evPipe);
    g_pipe.state = PipeState::Listening;
    if (!ConnectNamedPipe(g_pipe.h, &g_pipe.ov)) {
        const DWORD e = GetLastError();
        if (e == ERROR_PIPE_CONNECTED) SetEvent(g_evPipe);
        else if (e != ERROR_IO_PENDING) g_pipe.state = PipeState::Off;
    }
}

void PipeStartRead() {
    ZeroMemory(&g_pipe.ov, sizeof g_pipe.ov);
    g_pipe.ov.hEvent = g_evPipe;
    ResetEvent(g_evPipe);
    g_pipe.state = PipeState::Reading;
    if (!ReadFile(g_pipe.h, g_pipe.req, (kPipeReqChars - 1) * sizeof(wchar_t), nullptr, &g_pipe.ov) &&
        GetLastError() != ERROR_IO_PENDING)
        PipeReset();
}

void PipeStartWrite() {
    ZeroMemory(&g_pipe.ov, sizeof g_pipe.ov);
    g_pipe.ov.hEvent = g_evPipe;
    ResetEvent(g_evPipe);
    g_pipe.state = PipeState::Writing;
    const DWORD bytes = static_cast<DWORD>(wcslen(g_pipe.rsp) * sizeof(wchar_t));
    if (!WriteFile(g_pipe.h, g_pipe.rsp, bytes, nullptr, &g_pipe.ov) && GetLastError() != ERROR_IO_PENDING)
        PipeReset();
}

// Statusantwort: Tab-getrennte Zeilen (Format siehe gui.cpp, ParseStatus).
void BuildStatus(SvcState& st, wchar_t* out, size_t cap) {
    out[0] = 0;
    const wchar_t* mode = st.pausedUntil ? L"paused" : st.manual ? L"manual" : L"auto";
    wchar_t f1[kDnsLen], f2[kDnsLen], f3[kDnsLen];
    Appendf(out, cap, L"V\t2\nSVC\t%ls\t%llu\t%ls\n", mode, st.pausedUntil, st.manual ? st.manualTunnel : L"");
    SanitizeField(st.cfgErr, f1, _countof(f1));
    Appendf(out, cap, L"CFG\t%d\t%ls\n", st.cfgValid ? 1 : 0, f1);
    Appendf(out, cap, L"OPT\t%u\t%d\t%d\t%ls\n", g_cfg.debounceMs, g_cfg.noNetworkOn ? 1 : 0, g_cfg.captiveWait ? 1 : 0,
            g_cfg.defaultTunnel >= 0 ? g_cfg.tunnels[g_cfg.defaultTunnel] : L"");
    Appendf(out, cap, L"TARGET\t%ls\t%d\t%d\nCONN\t%d\n", st.lastTarget, st.lastDecision.captiveHold ? 1 : 0,
            st.lastDecision.failSafe ? 1 : 0, static_cast<int>(st.lastConn));
    SanitizeField(st.lastWhy, f1, _countof(f1));
    Appendf(out, cap, L"WHY\t%ls\n", f1);

    for (int i = 0; i < g_snap.n; ++i) {
        const IfInfo& f = g_snap.ifs[i];
        wchar_t mac[24] = L"", bssid[24] = L"";
        if (f.hasMac) MacToStr(f.gwMac, mac, _countof(mac));
        if (f.hasBssid) MacToStr(f.bssid, bssid, _countof(bssid));
        SanitizeField(f.alias, f1, _countof(f1));
        SanitizeField(f.hasSsid ? f.ssid : L"", f2, _countof(f2));
        SanitizeField(f.dnsSuffix, f3, _countof(f3));
        const int r = MatchRule(g_cfg, f);
        Appendf(out, cap, L"IF\t%d\t%ls\t%ls\t%ls\t%ls\t%ls\t%ls\n", static_cast<int>(f.kind), f1, mac, f3, f2,
                bssid, r >= 0 ? g_cfg.rules[r].name : L"");
    }

    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
    EnumTunnels(scm, &g_cfg, g_known);
    for (int i = 0; i < g_known.n; ++i) {
        ULONG64 rx = 0, tx = 0;
        const TState s = scm ? QueryTunnel(scm, g_known.names[i]) : TState::Error;
        if (s == TState::Running) TunnelTraffic(g_known.names[i], rx, tx);
        Appendf(out, cap, L"TUN\t%ls\t%d\t%llu\t%llu\n", g_known.names[i], static_cast<int>(s), rx, tx);
    }
    if (scm) CloseServiceHandle(scm);

    if (st.cfgValid) {
        for (int i = 0; i < g_cfg.ruleCount; ++i) {
            const Rule& r = g_cfg.rules[i];
            wchar_t mac[24] = L"", bssid[24] = L"";
            if (r.hasMac) MacToStr(r.gwMac, mac, _countof(mac));
            if (r.hasBssid) MacToStr(r.bssid, bssid, _countof(bssid));
            SanitizeField(r.hasSsid ? r.ssid : L"", f2, _countof(f2));
            Appendf(out, cap, L"RULE\t%ls\t%d\t%ls\t%ls\t%ls\t%ls\t%ls\n", r.name, r.hasKind ? static_cast<int>(r.kind) : -1,
                    f2, bssid, mac, r.hasDns ? r.dnsSuffix : L"", r.tunnel == kNoTunnel ? L"none" : g_cfg.tunnels[r.tunnel]);
        }
    }
}

// Bearbeitet eine Anfrage. Erlaubt: status, connect <tunnel>, disconnect, auto, pause <min>, resume, reload.
void HandleRequest(SvcState& st, wchar_t* req, wchar_t* rsp, size_t cap) {
    wchar_t* p = req;
    const wchar_t* cmd = NextField(p);
    const wchar_t* arg = NextField(p);
    rsp[0] = 0;
    if (StrEq(cmd, L"status")) { BuildStatus(st, rsp, cap); return; }

    if (StrEq(cmd, L"connect") || StrEq(cmd, L"disconnect")) {
        const bool connect = StrEq(cmd, L"connect");
        if (connect) {
            SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
            EnumTunnels(scm, &g_cfg, g_known);
            if (scm) CloseServiceHandle(scm);
            if (!IsValidTunnelName(arg) || FindKnown(g_known, arg) < 0) {
                swprintf_s(rsp, cap, L"ERR\tUnbekannter Tunnel.");
                return;
            }
        }
        st.manual = true;
        st.manualFp = st.lastFp;
        StrCopy(st.manualTunnel, kNameLen, connect ? arg : L"");
        StrCopy(st.lastTarget, kNameLen, st.manualTunnel);
        Log(EVENTLOG_INFORMATION_TYPE, connect ? L"Manuell verbunden: \"%ls\" (gilt bis zum naechsten Netzwechsel)."
                                               : L"Manuell getrennt%ls (gilt bis zum naechsten Netzwechsel).", st.manualTunnel);
        const DWORD e = ApplyTunnel(st.manualTunnel, L"(manuell)");
        if (e == NO_ERROR) swprintf_s(rsp, cap, L"OK");
        else swprintf_s(rsp, cap, L"ERR\tTunnel konnte nicht geschaltet werden (Fehler %lu).", e);
        PulseState();
        return;
    }
    if (StrEq(cmd, L"auto")) {
        st.manual = false;
        if (!st.pausedUntil) Evaluate(st, false);
        swprintf_s(rsp, cap, L"OK");
        return;
    }
    if (StrEq(cmd, L"pause") || StrEq(cmd, L"resume")) {
        unsigned minutes = 0;
        if (StrEq(cmd, L"pause") && (!ParseUInt(arg, minutes) || minutes > 1440)) {
            swprintf_s(rsp, cap, L"ERR\tMinuten 0..1440.");
            return;
        }
        SetPause(st, minutes);
        if (!st.pausedUntil) Evaluate(st, false);
        PulseState();
        swprintf_s(rsp, cap, L"OK");
        return;
    }
    if (StrEq(cmd, L"reload")) {
        LoadState(st);
        if (!st.pausedUntil) ArmTimer(g_tmDebounce, g_cfg.debounceMs);
        swprintf_s(rsp, cap, L"OK");
        return;
    }
    swprintf_s(rsp, cap, L"ERR\tUnbekannter Befehl.");
}

void PipeOnEvent(SvcState& st) {
    DWORD n = 0;
    const BOOL ok = GetOverlappedResult(g_pipe.h, &g_pipe.ov, &n, FALSE);
    switch (g_pipe.state) {
    case PipeState::Listening:
        if (!ok && GetLastError() != ERROR_PIPE_CONNECTED) { PipeReset(); return; }
        ArmTimer(g_tmPipe, kPipeIdleMs);
        PipeStartRead();
        return;
    case PipeState::Reading:
        if (!ok) { PipeReset(); return; }   // Client hat geschlossen, Nachricht zu gross, ...
        g_pipe.req[n / sizeof(wchar_t)] = 0;
        HandleRequest(st, g_pipe.req, g_pipe.rsp, _countof(g_pipe.rsp));
        ArmTimer(g_tmPipe, kPipeIdleMs);
        PipeStartWrite();
        return;
    case PipeState::Writing:
        if (!ok) { PipeReset(); return; }
        PipeStartRead();                     // weitere Anfrage oder Verbindungsende abwarten
        return;
    default:
        return;
    }
}

bool PipeCreate() {
    // Lokal, nur SYSTEM, Administratoren und interaktive Benutzer; Netzwerkanmeldungen verweigert.
    SECURITY_ATTRIBUTES sa;
    if (!CreateSa(L"D:P(D;;GA;;;NU)(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)", sa)) return false;
    g_pipe.h = CreateNamedPipeW(kPipeName, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
                                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1,
                                kPipeRspChars * sizeof(wchar_t), kPipeReqChars * sizeof(wchar_t), 0, &sa);
    LocalFree(sa.lpSecurityDescriptor);
    if (g_pipe.h == INVALID_HANDLE_VALUE) return false;
    PipeListen();
    return true;
}

// =====================================================================================
// Dienst: Rahmen
// =====================================================================================

bool IsWireGuardLuid(const NET_LUID& luid) {
    MIB_IF_ROW2 r;
    ZeroMemory(&r, sizeof r);
    r.InterfaceLuid = luid;
    if (GetIfEntry2(&r) != NO_ERROR) return false;
    return wcsstr(r.Description, L"WireGuard") != nullptr;
}

// Benachrichtigungen laufen auf Threads des Systems: nur filtern und Ereignis setzen.
VOID WINAPI OnIpInterface(PVOID, PMIB_IPINTERFACE_ROW row, MIB_NOTIFICATION_TYPE) {
    if (row && IsWireGuardLuid(row->InterfaceLuid)) return;    // F7: keine Rueckkopplung
    SetEvent(g_evNet);
}

VOID WINAPI OnUnicastAddress(PVOID, PMIB_UNICASTIPADDRESS_ROW row, MIB_NOTIFICATION_TYPE) {
    if (row) {
        if (row->SuffixOrigin == IpSuffixOriginRandom) return;   // temporaere IPv6-Adressen
        if (IsWireGuardLuid(row->InterfaceLuid)) return;
    }
    SetEvent(g_evNet);
}

VOID WINAPI OnConnectivityHint(PVOID, NL_NETWORK_CONNECTIVITY_HINT) {
    SetEvent(g_evNet);
}

DWORD WINAPI CtrlHandler(DWORD ctrl, DWORD type, LPVOID, LPVOID) {
    switch (ctrl) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        SetEvent(g_evStop);
        return NO_ERROR;
    case SERVICE_CONTROL_INTERROGATE:
        return NO_ERROR;
    case SERVICE_CONTROL_POWEREVENT:
        if (type == PBT_APMRESUMEAUTOMATIC) SetEvent(g_evNet);              // einmal neu bewerten
        else if (type == PBT_APMSUSPEND) CancelWaitableTimer(g_tmDebounce); // im Standby nichts tun
        return NO_ERROR;
    case kCtrlReload:
        SetEvent(g_evReload);
        return NO_ERROR;
    default:
        return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

VOID WINAPI ServiceMain(DWORD, LPWSTR*) {
    g_ssh = RegisterServiceCtrlHandlerExW(kSvcName, CtrlHandler, nullptr);
    if (!g_ssh) return;
    SetSvcStatus(SERVICE_START_PENDING, NO_ERROR, 5000);
    EnterLowPowerMode();

    g_evStop     = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    g_evNet      = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    g_evReload   = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    g_evPipe     = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    g_tmDebounce = CreateWaitableTimerW(nullptr, FALSE, nullptr);
    g_tmRetry    = CreateWaitableTimerW(nullptr, FALSE, nullptr);
    g_tmPause    = CreateWaitableTimerW(nullptr, FALSE, nullptr);
    g_tmPipe     = CreateWaitableTimerW(nullptr, FALSE, nullptr);
    if (!g_evStop || !g_evNet || !g_evReload || !g_evPipe || !g_tmDebounce || !g_tmRetry || !g_tmPause ||
        !g_tmPipe || !InitPaths(g_paths)) {
        SetSvcStatus(SERVICE_STOPPED, ERROR_NOT_ENOUGH_MEMORY);
        return;
    }
    SECURITY_ATTRIBUTES sa;
    if (CreateSa(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x00100000;;;IU)", sa)) {   // IU: nur SYNCHRONIZE
        g_stateEvent = CreateEventW(&sa, TRUE, FALSE, kStateEvent);
        LocalFree(sa.lpSecurityDescriptor);
    }

    SvcState& st = g_st;
    ZeroBytes(&st, sizeof st);
    LoadState(st);

    g_pipe.h = INVALID_HANDLE_VALUE;
    if (!PipeCreate()) Log(EVENTLOG_WARNING_TYPE, L"Status-Pipe nicht verfuegbar (Fehler %lu); Oberflaeche ohne Verbindung.", GetLastError());

    HANDLE hIf = nullptr, hAddr = nullptr, hHint = nullptr;
    const DWORD e1 = NotifyIpInterfaceChange(AF_UNSPEC, OnIpInterface, nullptr, FALSE, &hIf);
    const DWORD e2 = NotifyUnicastIpAddressChange(AF_UNSPEC, OnUnicastAddress, nullptr, FALSE, &hAddr);
    const DWORD e3 = NotifyNetworkConnectivityHintChange(OnConnectivityHint, nullptr, FALSE, &hHint);
    if (e1 != NO_ERROR || e2 != NO_ERROR || e3 != NO_ERROR)
        Log(EVENTLOG_ERROR_TYPE, L"Netzwerk-Benachrichtigungen unvollstaendig (%lu/%lu/%lu).", e1, e2, e3);

    SetSvcStatus(SERVICE_RUNNING);
    Log(EVENTLOG_INFORMATION_TYPE, L"WG-AutoSwitch gestartet: %d Regeln, Standardtunnel \"%ls\".",
        g_cfg.ruleCount, TunnelLabel(g_cfg, g_cfg.defaultTunnel));
    Evaluate(st, false);

    HANDLE hs[8] = { g_evStop, g_evNet, g_evReload, g_tmDebounce, g_tmRetry, g_tmPause, g_evPipe, g_tmPipe };
    const DWORD count = g_pipe.h != INVALID_HANDLE_VALUE ? 8 : 6;
    bool run = true;
    while (run) {
        // Einziger Wartepunkt: ohne Timeout -> keine Weckungen im Leerlauf.
        const DWORD w = WaitForMultipleObjects(count, hs, FALSE, INFINITE);
        switch (w) {
        case WAIT_OBJECT_0 + 0: run = false; break;                                   // Stopp
        case WAIT_OBJECT_0 + 1: if (!st.pausedUntil) ArmTimer(g_tmDebounce, g_cfg.debounceMs); break;  // F6
        case WAIT_OBJECT_0 + 2:                                                       // SCM-Reload
            LoadState(st);
            if (!st.pausedUntil) ArmTimer(g_tmDebounce, g_cfg.debounceMs);
            break;
        case WAIT_OBJECT_0 + 3: if (!st.pausedUntil) Evaluate(st, false); break;     // Ruhe erreicht
        case WAIT_OBJECT_0 + 4: if (!st.pausedUntil) Evaluate(st, true); break;      // Wiederholung
        case WAIT_OBJECT_0 + 5:                                                       // Pause vorbei
            st.pausedUntil = 0;
            Log(EVENTLOG_INFORMATION_TYPE, L"Pause beendet.");
            Evaluate(st, false);
            break;
        case WAIT_OBJECT_0 + 6: PipeOnEvent(st); break;                               // Pipe
        case WAIT_OBJECT_0 + 7: PipeReset(); break;                                   // Pipe-Zeitlimit
        default: run = false; break;   // WAIT_FAILED: sauber beenden statt CPU-Schleife
        }
    }

    SetSvcStatus(SERVICE_STOP_PENDING, NO_ERROR, 3000);
    if (hIf)   CancelMibChangeNotify2(hIf);
    if (hAddr) CancelMibChangeNotify2(hAddr);
    if (hHint) CancelMibChangeNotify2(hHint);
    if (g_pipe.h != INVALID_HANDLE_VALUE) { CancelIo(g_pipe.h); CloseHandle(g_pipe.h); }
    PulseState();
    Log(EVENTLOG_INFORMATION_TYPE, L"WG-AutoSwitch beendet.");
    SetSvcStatus(SERVICE_STOPPED);
}

int RunService() {
    SERVICE_TABLE_ENTRYW table[] = {
        { const_cast<LPWSTR>(kSvcName), ServiceMain },
        { nullptr, nullptr },
    };
    if (!StartServiceCtrlDispatcherW(table)) {
        PrintError(L"\"wgas service\" wird nur vom Dienststeuerungs-Manager gestartet", GetLastError());
        return 1;
    }
    return 0;
}

// =====================================================================================
// CLI-Helfer
// =====================================================================================

bool IsElevatedAdmin() {
    BYTE sid[SECURITY_MAX_SID_SIZE];
    DWORD cb = sizeof sid;
    if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, sid, &cb)) return false;
    BOOL member = FALSE;
    return CheckTokenMembership(nullptr, sid, &member) && member;
}

bool RequireAdmin() {
    if (IsElevatedAdmin()) return true;
    Err(L"Dieser Befehl braucht eine Eingabeaufforderung \"Als Administrator ausfuehren\".\n");
    return false;
}

DWORD SendControl(DWORD code) {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return GetLastError();
    SC_HANDLE svc = OpenServiceW(scm, kSvcName, SERVICE_USER_DEFINED_CONTROL);
    DWORD e = NO_ERROR;
    if (!svc) e = GetLastError();
    else {
        SERVICE_STATUS ss;
        if (!ControlService(svc, code, &ss)) e = GetLastError();
        CloseServiceHandle(svc);
    }
    CloseServiceHandle(scm);
    return e;
}

void NotifyService() {
    const DWORD e = SendControl(kCtrlReload);
    if (e == NO_ERROR) Out(L"Dienst hat die Aenderung uebernommen.\n");
    else if (e == ERROR_SERVICE_NOT_ACTIVE) Out(L"Hinweis: Dienst laeuft nicht (\"sc start WgAutoSwitch\").\n");
    else if (e == ERROR_SERVICE_DOES_NOT_EXIST) Out(L"Hinweis: Dienst ist noch nicht installiert (\"wgas install\").\n");
    else PrintError(L"Dienst benachrichtigen", e);
}

DWORD RunWireGuard(const wchar_t* verb, const wchar_t* arg) {
    if (!FileExists(g_paths.wgExe)) return ERROR_FILE_NOT_FOUND;
    wchar_t cmd[MAX_PATH * 2 + 64];
    swprintf_s(cmd, _countof(cmd), L"\"%ls\" %ls \"%ls\"", g_paths.wgExe, verb, arg);
    STARTUPINFOW si;
    ZeroMemory(&si, sizeof si);
    si.cb = sizeof si;
    PROCESS_INFORMATION pi;
    if (!CreateProcessW(g_paths.wgExe, cmd, nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
        return GetLastError();
    DWORD code = ERROR_TIMEOUT;
    if (WaitForSingleObject(pi.hProcess, 60000) == WAIT_OBJECT_0) GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return code;
}

// Dienst-ACL des Tunnel-Dienstes um Start/Stop/Status fuer NT SERVICE\WgAutoSwitch ergaenzen.
bool GrantServiceControl(SC_HANDLE svc, const wchar_t* sid) {
    DWORD need = 0;
    BYTE probe[8];
    QueryServiceObjectSecurity(svc, DACL_SECURITY_INFORMATION, probe, 0, &need);
    if (!need) return false;
    HANDLE heap = GetProcessHeap();
    PSECURITY_DESCRIPTOR sd = HeapAlloc(heap, 0, need);
    LPWSTR str = nullptr;
    bool ok = false;
    if (sd && QueryServiceObjectSecurity(svc, DACL_SECURITY_INFORMATION, sd, need, &need) &&
        ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &str, nullptr)) {
        if (wcsstr(str, sid)) {
            ok = true;
        } else {
            const size_t len = wcslen(str) + wcslen(sid) + 32;
            wchar_t* ns = static_cast<wchar_t*>(HeapAlloc(heap, 0, len * sizeof(wchar_t)));
            if (ns) {
                // RP = SERVICE_START, WP = SERVICE_STOP, LC = SERVICE_QUERY_STATUS - nicht mehr.
                swprintf_s(ns, len, L"%ls(A;;RPWPLC;;;%ls)", str, sid);
                PSECURITY_DESCRIPTOR nsd = nullptr;
                if (ConvertStringSecurityDescriptorToSecurityDescriptorW(ns, SDDL_REVISION_1, &nsd, nullptr)) {
                    ok = SetServiceObjectSecurity(svc, DACL_SECURITY_INFORMATION, nsd) != FALSE;
                    LocalFree(nsd);
                }
                HeapFree(heap, 0, ns);
            }
        }
    }
    if (str) LocalFree(str);
    if (sd) HeapFree(heap, 0, sd);
    return ok;
}

// Tunnel-Dienst vorbereiten: Starttyp "Manuell" + Rechte fuer unseren Dienst.
bool PrepareTunnelService(SC_HANDLE scm, const wchar_t* tunnel, const wchar_t* svcSid) {
    wchar_t name[64];
    TunnelSvcName(tunnel, name, _countof(name));
    SC_HANDLE h = OpenServiceW(scm, name, READ_CONTROL | WRITE_DAC | SERVICE_CHANGE_CONFIG);
    if (!h) return false;
    bool ok = ChangeServiceConfigW(h, SERVICE_NO_CHANGE, SERVICE_DEMAND_START, SERVICE_NO_CHANGE,
                                   nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr) != FALSE;
    if (svcSid && svcSid[0]) ok = GrantServiceControl(h, svcSid) && ok;
    CloseServiceHandle(h);
    return ok;
}

// Alle installierten WireGuard-Tunnel vorbereiten.
void PrepareAllTunnels(const wchar_t* svcSid) {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) return;
    wchar_t err[512];
    const bool cfgOk = LoadConfig(g_paths.cfg, g_cfg, err, _countof(err));
    EnumTunnels(scm, cfgOk ? &g_cfg : nullptr, g_known);
    for (int i = 0; i < g_known.n; ++i)
        if (QueryTunnel(scm, g_known.names[i]) != TState::Missing) PrepareTunnelService(scm, g_known.names[i], svcSid);
    CloseServiceHandle(scm);
}

constexpr wchar_t kExampleConfig[] =
    L"; WG-AutoSwitch - Konfiguration\r\n"
    L"; Am einfachsten in der Oberflaeche (wgas-gui.exe, Reiter Auto-Tunneling) bearbeiten.\r\n"
    L"; Von Hand: als UTF-16 LE speichern (Umlaute in SSIDs), danach: wgas reload\r\n"
    L"\r\n"
    L"[general]\r\n"
    L"default_tunnel = wg-home    ; Tunnel fuer unbekannte Netze (Fail-safe)\r\n"
    L"debounce_ms = 2500          ; Ruhezeit vor dem Entscheid\r\n"
    L"no_network = off            ; off: ohne Netz Tunnel aus (spart Energie)\r\n"
    L"captive_portal = wait       ; wait: Tunnel erst nach Hotel-/Zug-Anmeldung\r\n"
    L"\r\n"
    L"; Regeln: erste passende gewinnt. Alle angegebenen Merkmale muessen passen.\r\n"
    L"; tunnel = none (kein Tunnel) braucht gateway_mac UND dns_suffix, ssid oder bssid.\r\n"
    L";[network.home-lan]\r\n"
    L";type = ethernet\r\n"
    L";gateway_mac = 00:11:22:33:44:55\r\n"
    L";dns_suffix = home.lan\r\n"
    L";tunnel = none\r\n";

void PrintSnapshot(const Config* c, const Snapshot& s, Connectivity conn) {
    if (!s.ok) { Out(L"  Netzwerkzustand nicht lesbar.\n"); return; }
    if (s.n == 0) Out(L"  Keine verbundene Schnittstelle mit Gateway.\n");
    for (int i = 0; i < s.n; ++i) {
        const IfInfo& f = s.ifs[i];
        wchar_t mac[24];
        Out(L"  [%ls] %ls\n", KindName(f.kind), f.alias);
        MacToStr(f.gwMac, mac, _countof(mac));
        Out(L"      Gateway-MAC : %ls\n", f.hasMac ? mac : L"(nicht ermittelbar)");
        Out(L"      DNS-Suffix  : %ls\n", f.dnsSuffix[0] ? f.dnsSuffix : L"(keines)");
        if (f.kind == IfKind::Wifi) {
            Out(L"      SSID        : %ls\n", f.hasSsid ? f.ssid : L"(nicht lesbar - Standortdienste?)");
            MacToStr(f.bssid, mac, _countof(mac));
            Out(L"      BSSID       : %ls\n", f.hasBssid ? mac : L"(nicht lesbar)");
        }
        if (c) {
            const int r = MatchRule(*c, f);
            if (r >= 0) Out(L"      Regel       : network.%ls -> %ls\n", c->rules[r].name, TunnelLabel(*c, c->rules[r].tunnel));
            else        Out(L"      Regel       : keine passende -> Standard %ls\n", TunnelLabel(*c, c->defaultTunnel));
        }
    }
    Out(L"  Konnektivitaet: %ls\n", ConnName(conn));
}

void PrintSuggestions(const Config* c, const Snapshot& s) {
    int k = 0;
    for (int i = 0; i < s.n; ++i) {
        const IfInfo& f = s.ifs[i];
        if (c && MatchRule(*c, f) >= 0) continue;
        if (k++ == 0) Out(L"\nVorschlag fuer config.ini (Name anpassen; tunnel = none oder ein Tunnelname):\n");
        Out(L"\n[network.netz-%d]\ntype = %ls\n", k, KindKey(f.kind));
        if (f.hasSsid) Out(L"ssid = %ls\n", f.ssid);
        wchar_t mac[24];
        if (f.hasMac) { MacToStr(f.gwMac, mac, _countof(mac)); Out(L"gateway_mac = %ls\n", mac); }
        if (f.dnsSuffix[0]) Out(L"dns_suffix = %ls\n", f.dnsSuffix);
        Out(L"tunnel = none\n");
        if (!f.hasMac) Out(L"; ACHTUNG: Gateway-MAC nicht ermittelbar - dieses Netz kann nicht als vertraut gelten.\n");
        else if (!f.dnsSuffix[0] && !f.hasSsid)
            Out(L"; ACHTUNG: nur Gateway-MAC vorhanden - fuer tunnel = none fehlt ein zweites Merkmal.\n");
    }
}

// Warnt, wenn config.ini Nicht-ASCII enthaelt, aber nicht UTF-16 LE ist.
void CheckEncoding(const wchar_t* path) {
    HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (f == INVALID_HANDLE_VALUE) return;
    unsigned char b[4096];
    DWORD n = 0;
    const BOOL ok = ReadFile(f, b, sizeof b, &n, nullptr);
    CloseHandle(f);
    if (!ok || n < 2 || (b[0] == 0xFF && b[1] == 0xFE)) return;
    for (DWORD i = 0; i < n; ++i) {
        if (b[i] >= 0x80) {
            Out(L"WARNUNG: config.ini enthaelt Sonderzeichen, ist aber nicht als UTF-16 LE gespeichert.\n"
                L"         Umlaute in SSIDs werden falsch gelesen. Editor: Speichern unter > Codierung UTF-16 LE.\n");
            return;
        }
    }
}

// Prueft config.ini; bei Erfolg wird der Standardtunnel als Fail-safe gemerkt.
// 0 = ungueltig, 1 = gueltig aber Tunnel fehlen, 2 = alles in Ordnung
int ValidateConfig(const wchar_t* path) {
    wchar_t err[512];
    if (!LoadConfig(path, g_cfg, err, _countof(err))) {
        Out(L"Konfiguration UNGUELTIG: %ls\n", err);
        return 0;
    }
    Out(L"Konfiguration gueltig: %d Regeln, Standardtunnel \"%ls\".\n", g_cfg.ruleCount, g_cfg.tunnels[g_cfg.defaultTunnel]);
    int result = 2;
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    for (int i = 0; scm && i < g_cfg.tunnelCount; ++i) {
        if (QueryTunnel(scm, g_cfg.tunnels[i]) == TState::Missing) {
            Out(L"WARNUNG: Tunnel \"%ls\" ist nicht installiert (wgas import <datei>.conf).\n", g_cfg.tunnels[i]);
            result = 1;
        }
    }
    if (scm) CloseServiceHandle(scm);
    return result;
}

bool StopAndWait(SC_HANDLE svc, DWORD timeoutMs) {
    SERVICE_STATUS ss;
    if (!ControlService(svc, SERVICE_CONTROL_STOP, &ss)) return GetLastError() == ERROR_SERVICE_NOT_ACTIVE;
    WaitWhile(svc, SERVICE_STOP_PENDING, timeoutMs);
    return true;
}

bool WaitServiceExists(SC_HANDLE scm, const wchar_t* tunnel, bool exists) {
    for (int i = 0; i < 100; ++i) {
        const TState s = QueryTunnel(scm, tunnel);
        if ((s != TState::Missing) == exists) return true;
        Sleep(100);
    }
    return false;
}

// =====================================================================================
// CLI-Befehle
// =====================================================================================

int CmdInstall() {
    if (!RequireAdmin()) return 1;
    if (!FileExists(g_paths.wgExe))
        Out(L"WARNUNG: WireGuard fuer Windows nicht gefunden (%ls).\n"
            L"         Bitte zuerst installieren: https://www.wireguard.com/install/ (ARM64-MSI)\n", g_paths.wgExe);

    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE | SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) { PrintError(L"Dienststeuerung oeffnen", GetLastError()); return 1; }
    SC_HANDLE svc = OpenServiceW(scm, kSvcName, SERVICE_ALL_ACCESS);
    if (svc) StopAndWait(svc, 15000);   // Aktualisierung: alte Version anhalten

    // 1. Programme nach %ProgramFiles%\WgAutoSwitch (nur Admins duerfen dort schreiben)
    wchar_t self[MAX_PATH];
    const DWORD n = GetModuleFileNameW(nullptr, self, MAX_PATH);
    if (!n || n >= MAX_PATH) { PrintError(L"Eigener Pfad", GetLastError()); return 1; }
    CreateDirectoryW(g_paths.progDir, nullptr);
    if (_wcsicmp(self, g_paths.exe) != 0) {
        if (!CopyFileW(self, g_paths.exe, FALSE)) { PrintError(L"Kopieren nach Programme", GetLastError()); return 1; }
        // Oberflaeche aus demselben Ordner mitnehmen, falls vorhanden.
        wchar_t gui[MAX_PATH];
        StrCopy(gui, MAX_PATH, self);
        wchar_t* slash = wcsrchr(gui, L'\\');
        if (slash) {
            swprintf_s(slash + 1, static_cast<size_t>(MAX_PATH - (slash + 1 - gui)), L"wgas-gui.exe");
            if (FileExists(gui) && !CopyFileW(gui, g_paths.guiExe, FALSE))
                Out(L"WARNUNG: wgas-gui.exe liess sich nicht kopieren (laeuft sie noch? Im Tray beenden).\n");
        }
    }

    // 2. Dienst anlegen: zuerst ohne Konto, dann Dienst-SID + virtuelles Konto
    wchar_t bin[MAX_PATH + 32];
    swprintf_s(bin, _countof(bin), L"\"%ls\" service", g_paths.exe);
    if (!svc) {
        svc = CreateServiceW(scm, kSvcName, kSvcDisplay, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START,
                             SERVICE_ERROR_NORMAL, bin, nullptr, nullptr, nullptr, nullptr, nullptr);
        if (!svc) { PrintError(L"Dienst anlegen", GetLastError()); return 1; }
    } else if (!ChangeServiceConfigW(svc, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, bin,
                                     nullptr, nullptr, nullptr, nullptr, nullptr, kSvcDisplay)) {
        PrintError(L"Dienst aktualisieren", GetLastError());
        return 1;
    }
    SERVICE_SID_INFO sidInfo;
    sidInfo.dwServiceSidType = SERVICE_SID_TYPE_UNRESTRICTED;
    ChangeServiceConfig2W(svc, SERVICE_CONFIG_SERVICE_SID_INFO, &sidInfo);
    if (!ChangeServiceConfigW(svc, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE, nullptr, nullptr, nullptr,
                              nullptr, kSvcAccount, nullptr, nullptr)) {
        PrintError(L"Virtuelles Dienstkonto setzen", GetLastError());
        return 1;
    }
    SERVICE_DESCRIPTIONW desc;
    desc.lpDescription = const_cast<LPWSTR>(kSvcDescription);
    ChangeServiceConfig2W(svc, SERVICE_CONFIG_DESCRIPTION, &desc);
    // Mindestrechte; SeCreateGlobalPrivilege fuer das Zustandssignal an die Oberflaeche.
    SERVICE_REQUIRED_PRIVILEGES_INFOW priv;
    priv.pmszRequiredPrivileges = const_cast<LPWSTR>(L"SeChangeNotifyPrivilege\0SeCreateGlobalPrivilege\0");
    ChangeServiceConfig2W(svc, SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO, &priv);
    SC_ACTION acts[2] = { { SC_ACTION_RESTART, 60000 }, { SC_ACTION_RESTART, 60000 } };
    SERVICE_FAILURE_ACTIONSW fa;
    ZeroMemory(&fa, sizeof fa);
    fa.dwResetPeriod = 86400;
    fa.cActions = 2;
    fa.lpsaActions = acts;
    ChangeServiceConfig2W(svc, SERVICE_CONFIG_FAILURE_ACTIONS, &fa);

    // 3. Ereignisquelle (Meldungstext steckt als Ressource in wgas.exe)
    HKEY k;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, kEvtKey, 0, nullptr, 0, KEY_SET_VALUE, nullptr, &k, nullptr) == ERROR_SUCCESS) {
        RegSetValueExW(k, L"EventMessageFile", 0, REG_EXPAND_SZ, reinterpret_cast<const BYTE*>(g_paths.exe),
                       static_cast<DWORD>((wcslen(g_paths.exe) + 1) * sizeof(wchar_t)));
        const DWORD types = EVENTLOG_ERROR_TYPE | EVENTLOG_WARNING_TYPE | EVENTLOG_INFORMATION_TYPE;
        RegSetValueExW(k, L"TypesSupported", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&types), sizeof types);
        RegCloseKey(k);
    }
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, kRegKey, 0, nullptr, 0, KEY_READ, nullptr, &k, nullptr) == ERROR_SUCCESS)
        RegCloseKey(k);

    // 4. Datenordner, Beispielkonfiguration, Dateirechte
    wchar_t sid[128];
    if (!GetServiceSidString(sid, _countof(sid))) { PrintError(L"Dienst-SID ermitteln", GetLastError()); return 1; }
    CreateDirectoryW(g_paths.dataDir, nullptr);
    CreateDirectoryW(g_paths.tunDir, nullptr);
    if (!FileExists(g_paths.cfg)) {
        WriteUtf16File(g_paths.cfg, kExampleConfig, true);
        Out(L"Beispielkonfiguration angelegt: %ls\n", g_paths.cfg);
    }
    if (!SecureDataDir(g_paths, sid)) PrintError(L"Dateirechte setzen", GetLastError());

    // 5. Vorhandene Tunnel: Starttyp Manuell + Start/Stop-Recht fuer den Dienst
    PrepareAllTunnels(sid);
    const int valid = ValidateConfig(g_paths.cfg);
    if (valid > 0) RegWriteFailsafe(g_cfg.tunnels[g_cfg.defaultTunnel]);

    // 6. Starten
    if (!StartServiceW(svc, 0, nullptr) && GetLastError() != ERROR_SERVICE_ALREADY_RUNNING)
        PrintError(L"Dienst starten", GetLastError());
    else
        Out(L"Dienst \"%ls\" installiert und gestartet (startet automatisch mit Windows).\n", kSvcName);
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);

    if (valid < 2 && !g_guiMode)
        Out(L"\nNaechste Schritte:\n"
            L"  1. %ls starten (Tray-Symbol)\n"
            L"  2. Tunnel importieren (Datei aus dem OPNsense-Peer-Generator)\n"
            L"  3. Reiter Auto-Tunneling: aktuelles Netz als vertraut speichern\n", g_paths.guiExe);
    return 0;
}

int CmdUninstall(bool purge) {
    if (!RequireAdmin()) return 1;
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) { PrintError(L"Dienststeuerung oeffnen", GetLastError()); return 1; }
    SC_HANDLE svc = OpenServiceW(scm, kSvcName, SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
    if (svc) {
        StopAndWait(svc, 15000);
        if (!DeleteService(svc)) PrintError(L"Dienst loeschen", GetLastError());
        CloseServiceHandle(svc);
        Out(L"Dienst entfernt.\n");
    }
    RegDeleteKeyW(HKEY_LOCAL_MACHINE, kEvtKey);
    RegDeleteKeyW(HKEY_LOCAL_MACHINE, kRegKey);
    HKEY run;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &run) == ERROR_SUCCESS) {
        RegDeleteValueW(run, L"WgAutoSwitchGui");
        RegCloseKey(run);
    }

    if (purge) {
        wchar_t pattern[MAX_PATH];
        swprintf_s(pattern, _countof(pattern), L"%ls\\*.conf", g_paths.tunDir);
        WIN32_FIND_DATAW fd;
        HANDLE f = FindFirstFileW(pattern, &fd);
        if (f != INVALID_HANDLE_VALUE) {
            do {
                wchar_t stem[MAX_PATH], file[MAX_PATH];
                StrCopy(stem, MAX_PATH, fd.cFileName);
                wchar_t* dot = wcsrchr(stem, L'.');
                if (dot) *dot = 0;
                if (IsValidTunnelName(stem) && QueryTunnel(scm, stem) != TState::Missing) {
                    StopTunnel(scm, stem);
                    RunWireGuard(L"/uninstalltunnelservice", stem);
                    Out(L"Tunnel \"%ls\" entfernt.\n", stem);
                }
                swprintf_s(file, _countof(file), L"%ls\\%ls", g_paths.tunDir, fd.cFileName);
                DeleteFileW(file);
            } while (FindNextFileW(f, &fd));
            FindClose(f);
        }
        wchar_t editDir[MAX_PATH];
        swprintf_s(editDir, _countof(editDir), L"%ls\\edit", g_paths.tunDir);
        RemoveDirectoryW(editDir);
        DeleteFileW(g_paths.cfg);
        RemoveDirectoryW(g_paths.tunDir);
        RemoveDirectoryW(g_paths.dataDir);
        Out(L"Konfiguration und Tunnel-Dateien entfernt.\n");
    } else {
        Out(L"Konfiguration und Tunnel bleiben erhalten (%ls). Alles entfernen: wgas uninstall /purge\n", g_paths.dataDir);
    }
    CloseServiceHandle(scm);

    wchar_t self[MAX_PATH];
    GetModuleFileNameW(nullptr, self, MAX_PATH);
    if (_wcsicmp(self, g_paths.exe) == 0) {
        MoveFileExW(g_paths.exe, nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);   // laufende Datei: beim Neustart
        if (!DeleteFileW(g_paths.guiExe)) MoveFileExW(g_paths.guiExe, nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
        MoveFileExW(g_paths.progDir, nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
        Out(L"%ls wird beim naechsten Neustart geloescht.\n", g_paths.progDir);
    } else {
        DeleteFileW(g_paths.exe);
        if (!DeleteFileW(g_paths.guiExe)) MoveFileExW(g_paths.guiExe, nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
        RemoveDirectoryW(g_paths.progDir);
    }
    return 0;
}

// Prueft eine wg-quick-/OPNsense-Konfiguration auf die Pflichtteile.
bool CheckTunnelConf(const wchar_t* path, const unsigned char* buf, DWORD len) {
    if (len >= 2 && buf[0] == 0xFF && buf[1] == 0xFE) {
        Err(L"Fehler: %ls ist UTF-16. Bitte als UTF-8 oder ANSI speichern.\n", path);
        return false;
    }
    static const char* const kNeedles[] = { "[interface]", "privatekey", "[peer]", "publickey", "endpoint" };
    for (const char* needle : kNeedles) {
        const size_t nl = strlen(needle);
        bool found = false;
        for (DWORD i = 0; !found && i + nl <= len; ++i) {
            size_t j = 0;
            while (j < nl) {
                char c = static_cast<char>(buf[i + j]);
                if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
                if (c != needle[j]) break;
                ++j;
            }
            found = j == nl;
        }
        if (!found) {
            Err(L"Fehler: %ls ist keine vollstaendige WireGuard-Konfiguration (\"%hs\" fehlt).\n", path, needle);
            return false;
        }
    }
    return true;
}

bool ReadTunnelConf(const wchar_t* path, unsigned char* buf, DWORD& len) {
    HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (f == INVALID_HANDLE_VALUE) { PrintError(path, GetLastError()); return false; }
    LARGE_INTEGER size;
    const bool ok = GetFileSizeEx(f, &size) && size.QuadPart > 0 && size.QuadPart <= kMaxConfBytes &&
                    ReadFile(f, buf, static_cast<DWORD>(size.QuadPart), &len, nullptr) && len == size.QuadPart;
    CloseHandle(f);
    if (!ok) { Err(L"Fehler: %ls ist leer, zu gross oder nicht lesbar.\n", path); return false; }
    return CheckTunnelConf(path, buf, len);
}

int CmdImport(int count, wchar_t** files) {
    if (!RequireAdmin()) return 1;
    if (!FileExists(g_paths.wgExe)) { PrintError(L"WireGuard fuer Windows nicht installiert", ERROR_FILE_NOT_FOUND); return 1; }
    CreateDirectoryW(g_paths.dataDir, nullptr);
    CreateDirectoryW(g_paths.tunDir, nullptr);
    wchar_t sid[128] = L"";
    const bool haveSid = GetServiceSidString(sid, _countof(sid));
    if (haveSid) SecureDataDir(g_paths, sid);
    else ApplySddl(g_paths.tunDir, L"O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)");

    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) { PrintError(L"Dienststeuerung oeffnen", GetLastError()); return 1; }
    static unsigned char buf[kMaxConfBytes];
    wchar_t firstImported[kNameLen] = L"";
    int failures = 0;

    for (int i = 0; i < count; ++i) {
        const wchar_t* src = files[i];
        const wchar_t* base = src;
        for (const wchar_t* p = src; *p; ++p) if (*p == L'\\' || *p == L'/') base = p + 1;
        wchar_t stem[MAX_PATH];
        StrCopy(stem, MAX_PATH, base);
        wchar_t* dot = wcsrchr(stem, L'.');
        if (!dot || !StrIEq(dot, L".conf")) { Err(L"Fehler: %ls - erwartet wird eine .conf-Datei.\n", src); ++failures; continue; }
        *dot = 0;
        if (!IsValidTunnelName(stem)) {
            Err(L"Fehler: Dateiname \"%ls\" ist kein gueltiger Tunnelname (A-Z a-z 0-9 _ = + . -, max. 32).\n", base);
            ++failures;
            continue;
        }
        DWORD len = 0;
        if (!ReadTunnelConf(src, buf, len)) { ++failures; continue; }
        const DWORD skip = (len >= 3 && buf[0] == 0xEF && buf[1] == 0xBB && buf[2] == 0xBF) ? 3 : 0;   // UTF-8-BOM

        // Kopie im geschuetzten Tunnelordner (private Schluessel: nur SYSTEM/Admins)
        wchar_t dst[MAX_PATH];
        swprintf_s(dst, _countof(dst), L"%ls\\%ls.conf", g_paths.tunDir, stem);
        HANDLE f = CreateFileW(dst, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        DWORD written = 0;
        const bool wrote = f != INVALID_HANDLE_VALUE && WriteFile(f, buf + skip, len - skip, &written, nullptr) &&
                           written == len - skip;
        const DWORD writeErr = GetLastError();
        if (f != INVALID_HANDLE_VALUE) CloseHandle(f);
        SecureZeroMemory(buf, sizeof buf);
        if (!wrote) { PrintError(dst, writeErr); ++failures; continue; }
        ApplySddl(dst, L"O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)");

        if (QueryTunnel(scm, stem) != TState::Missing) {   // Tunnel gleichen Namens ersetzen
            StopTunnel(scm, stem);
            RunWireGuard(L"/uninstalltunnelservice", stem);
            WaitServiceExists(scm, stem, false);
            Out(L"Bestehender Tunnel \"%ls\" wird ersetzt.\n", stem);
        }
        const DWORD rc = RunWireGuard(L"/installtunnelservice", dst);
        if (rc != 0 || !WaitServiceExists(scm, stem, true)) {
            PrintError(L"wireguard.exe /installtunnelservice", rc ? rc : ERROR_SERVICE_DOES_NOT_EXIST);
            ++failures;
            continue;
        }
        // WireGuard startet den Tunnel sofort - ab jetzt entscheidet WG-AutoSwitch.
        if (!PrepareTunnelService(scm, stem, haveSid ? sid : nullptr))
            Out(L"WARNUNG: Rechte fuer \"%ls\" nicht vollstaendig gesetzt (erst \"wgas install\"?).\n", stem);
        StopTunnel(scm, stem);
        if (!firstImported[0]) StrCopy(firstImported, kNameLen, stem);
        Out(L"Tunnel \"%ls\" importiert.\n", stem);
    }

    if (firstImported[0]) {
        // Ist der Standardtunnel noch nicht installiert (Beispielkonfiguration), den ersten Import eintragen.
        wchar_t err[512];
        const bool cfgOk = LoadConfig(g_paths.cfg, g_cfg, err, _countof(err));
        if (FileExists(g_paths.cfg) &&
            (!cfgOk || QueryTunnel(scm, g_cfg.tunnels[g_cfg.defaultTunnel]) == TState::Missing)) {
            WritePrivateProfileStringW(L"general", L"default_tunnel", firstImported, g_paths.cfg);
            Out(L"default_tunnel = %ls in config.ini eingetragen.\n", firstImported);
        }
        if (LoadConfig(g_paths.cfg, g_cfg, err, _countof(err))) RegWriteFailsafe(g_cfg.tunnels[g_cfg.defaultTunnel]);
        if (!g_guiMode)
            Out(L"\nSICHERHEIT: Die Quelldatei enthaelt den privaten Schluessel. Bitte loeschen,\n"
                L"            die Kopie liegt geschuetzt in %ls.\n", g_paths.tunDir);
        NotifyService();
    }
    CloseServiceHandle(scm);
    return failures ? 1 : 0;
}

int CmdRemove(const wchar_t* name) {
    if (!RequireAdmin()) return 1;
    if (!IsValidTunnelName(name)) { Err(L"Ungueltiger Tunnelname.\n"); return 2; }
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) { PrintError(L"Dienststeuerung oeffnen", GetLastError()); return 1; }
    if (QueryTunnel(scm, name) != TState::Missing) {
        StopTunnel(scm, name);
        const DWORD rc = RunWireGuard(L"/uninstalltunnelservice", name);
        if (rc) PrintError(L"wireguard.exe /uninstalltunnelservice", rc);
    }
    CloseServiceHandle(scm);
    wchar_t file[MAX_PATH];
    swprintf_s(file, _countof(file), L"%ls\\%ls.conf", g_paths.tunDir, name);
    DeleteFileW(file);
    Out(L"Tunnel \"%ls\" entfernt.\n", name);
    wchar_t err[512];
    if (LoadConfig(g_paths.cfg, g_cfg, err, _countof(err)))
        for (int i = 0; i < g_cfg.tunnelCount; ++i)
            if (StrIEq(g_cfg.tunnels[i], name))
                Out(L"WARNUNG: config.ini verwendet \"%ls\" noch (Standardtunnel oder Regel) - bitte anpassen.\n", name);
    NotifyService();
    return 0;
}

// Uebernimmt eine von der Oberflaeche erzeugte Konfiguration (keine Geheimnisse darin).
int CmdSetConfig(const wchar_t* src) {
    if (!RequireAdmin()) return 1;
    if (!ValidateConfig(src)) return 1;
    CreateDirectoryW(g_paths.dataDir, nullptr);
    if (!CopyFileW(src, g_paths.cfg, FALSE)) { PrintError(L"config.ini schreiben", GetLastError()); return 1; }
    wchar_t sid[128];
    if (GetServiceSidString(sid, _countof(sid))) SecureDataDir(g_paths, sid);
    wchar_t err[512];
    if (LoadConfig(g_paths.cfg, g_cfg, err, _countof(err))) RegWriteFailsafe(g_cfg.tunnels[g_cfg.defaultTunnel]);
    DeleteFileW(src);
    NotifyService();
    return 0;
}

int CmdStatus() {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) { PrintError(L"Dienststeuerung oeffnen", GetLastError()); return 1; }
    SC_HANDLE svc = OpenServiceW(scm, kSvcName, SERVICE_QUERY_STATUS);
    if (!svc) Out(L"Dienst          : nicht installiert\n");
    else {
        SERVICE_STATUS ss;
        ZeroMemory(&ss, sizeof ss);
        QueryServiceStatus(svc, &ss);
        Out(L"Dienst          : %ls\n", ss.dwCurrentState == SERVICE_RUNNING ? L"laeuft"
                                    : ss.dwCurrentState == SERVICE_STOPPED ? L"gestoppt" : L"wechselt Zustand");
        CloseServiceHandle(svc);
    }
    // Modus vom Dienst (Pause/manuell)
    static wchar_t rsp[kPipeRspChars];
    if (PipeTransact(L"status", rsp, kPipeRspChars) == NO_ERROR) {
        wchar_t* line = rsp;
        while (*line) {
            wchar_t* end = line;
            while (*end && *end != L'\n') ++end;
            const bool last = *end == 0;
            *end = 0;
            wchar_t* p = line;
            const wchar_t* tag = NextField(p);
            if (StrEq(tag, L"SVC")) {
                const wchar_t* mode = NextField(p);
                const wchar_t* until = NextField(p);
                const wchar_t* man = NextField(p);
                if (StrEq(mode, L"paused")) {
                    wchar_t t[16];
                    FormatLocalTime(_wcstoui64(until, nullptr, 10), t, _countof(t));
                    Out(L"Automatik       : pausiert bis %ls\n", t);
                } else if (StrEq(mode, L"manual")) {
                    Out(L"Automatik       : manuell %ls bis zum naechsten Netzwechsel\n", man[0] ? man : L"getrennt");
                } else {
                    Out(L"Automatik       : aktiv\n");
                }
            }
            if (last) break;
            line = end + 1;
        }
    }

    wchar_t err[512];
    const bool cfgOk = LoadConfig(g_paths.cfg, g_cfg, err, _countof(err));
    if (!cfgOk) Out(L"Konfiguration   : %ls\n", err);
    EnumTunnels(scm, cfgOk ? &g_cfg : nullptr, g_known);
    for (int i = 0; i < g_known.n; ++i) {
        const TState s = QueryTunnel(scm, g_known.names[i]);
        Out(L"Tunnel %-9ls: %ls%ls\n", g_known.names[i],
            s == TState::Running ? L"AN" : s == TState::StartPending ? L"startet"
            : s == TState::Missing ? L"nicht installiert" : s == TState::Error ? L"?" : L"aus",
            cfgOk && StrIEq(g_known.names[i], g_cfg.tunnels[g_cfg.defaultTunnel]) ? L"  (Standard)" : L"");
    }
    CloseServiceHandle(scm);

    Out(L"\nAktuelle Netze:\n");
    CollectInterfaces(cfgOk ? &g_cfg : nullptr, g_snap);
    const Connectivity conn = QueryConnectivity();
    PrintSnapshot(cfgOk ? &g_cfg : nullptr, g_snap, conn);
    if (cfgOk) {
        const Decision d = Decide(g_cfg, g_snap.ifs, g_snap.ok ? g_snap.n : 0, conn, g_snap.ok);
        Out(L"\nSoll-Zustand    : %ls%ls\n", TunnelLabel(g_cfg, d.tunnel),
            d.captiveHold ? L" (wartet auf Captive-Portal-Anmeldung)" : d.failSafe ? L" (Fail-safe)" : L"");
    }
    return 0;
}

int CmdCheck() {
    if (!RequireAdmin()) return 1;
    Out(L"Datei: %ls\n", g_paths.cfg);
    wchar_t err[512];
    const bool secure = ConfigIsSecure(g_paths, err, _countof(err));
    if (!secure) Out(L"WARNUNG: %ls\n", err);
    CheckEncoding(g_paths.cfg);
    const bool valid = ValidateConfig(g_paths.cfg) > 0;
    if (valid) RegWriteFailsafe(g_cfg.tunnels[g_cfg.defaultTunnel]);

    Out(L"\nAktuelle Netze:\n");
    CollectInterfaces(valid ? &g_cfg : nullptr, g_snap);
    const Connectivity conn = QueryConnectivity();
    PrintSnapshot(valid ? &g_cfg : nullptr, g_snap, conn);
    if (valid) {
        const Decision d = Decide(g_cfg, g_snap.ifs, g_snap.ok ? g_snap.n : 0, conn, g_snap.ok);
        Out(L"\nEntscheid jetzt: %ls%ls\n", TunnelLabel(g_cfg, d.tunnel),
            d.captiveHold ? L" (wartet auf Captive-Portal-Anmeldung)" : L"");
    }
    PrintSuggestions(valid ? &g_cfg : nullptr, g_snap);
    return valid && secure ? 0 : 1;
}

int PipeCommand(const wchar_t* req) {
    wchar_t rsp[512];
    const DWORD e = PipeTransact(req, rsp, _countof(rsp));
    if (e != NO_ERROR) { PrintError(L"Dienst nicht erreichbar", e); return 1; }
    if (StartsWithI(rsp, L"ERR\t")) { Err(L"Fehler: %ls\n", rsp + 4); return 1; }
    Out(L"OK\n");
    return 0;
}

int CmdReload() {
    if (!RequireAdmin()) return 1;
    wchar_t sid[128];
    if (GetServiceSidString(sid, _countof(sid))) {
        if (!SecureDataDir(g_paths, sid)) PrintError(L"Dateirechte setzen", GetLastError());
        PrepareAllTunnels(sid);
    }
    CheckEncoding(g_paths.cfg);
    if (ValidateConfig(g_paths.cfg) == 0) {
        Out(L"Nicht uebernommen - der Dienst arbeitet mit der bisherigen Konfiguration weiter.\n");
        return 1;
    }
    RegWriteFailsafe(g_cfg.tunnels[g_cfg.defaultTunnel]);
    NotifyService();
    return 0;
}

void Usage() {
    Out(L"WG-AutoSwitch 1.1 - schaltet WireGuard-Tunnel je nach Netz\n\n"
        L"Oberflaeche: wgas-gui.exe (Tray). Kommandozeile:\n"
        L"  wgas install                 Dienst installieren und starten (Admin)\n"
        L"  wgas uninstall [/purge]      Dienst entfernen; /purge auch Tunnel und Konfiguration (Admin)\n"
        L"  wgas import <a.conf> [...]   Tunnel aus OPNsense-Peer-Generator importieren (Admin)\n"
        L"  wgas remove <tunnel>         Tunnel entfernen (Admin)\n"
        L"  wgas status                  Zustand, Netze und Soll-Zustand anzeigen\n"
        L"  wgas check                   config.ini pruefen, Merkmale des Netzes zeigen (Admin)\n"
        L"  wgas reload                  config.ini neu laden (Admin)\n"
        L"  wgas connect <tunnel>        manuell verbinden (bis zum naechsten Netzwechsel)\n"
        L"  wgas disconnect              manuell trennen (bis zum naechsten Netzwechsel)\n"
        L"  wgas auto                    manuelle Wahl aufheben\n"
        L"  wgas pause <minuten>         Automatik anhalten (0 = fortsetzen)\n\n"
        L"Konfiguration: %ls\n", g_paths.cfg);
}

// Per Doppelklick gestartet? Dann gehoert die Konsole nur diesem Prozess.
bool OwnsConsole() {
    DWORD ids[2];
    return GetConsoleProcessList(ids, 2) == 1;
}

int Dispatch(int argc, wchar_t** argv) {
    if (argc < 1) {
        Usage();
        if (!g_guiMode)
            Out(L"\nTipp: Die Oberflaeche wgas-gui.exe erledigt alles per Mausklick.\n"
                L"Kommandozeile: Start > \"cmd\" > Rechtsklick \"Als Administrator ausfuehren\".\n");
        return 2;
    }
    const wchar_t* cmd = argv[0];
    if (StrIEq(cmd, L"install"))   return CmdInstall();
    if (StrIEq(cmd, L"uninstall")) return CmdUninstall(argc >= 2 && (StrIEq(argv[1], L"/purge") || StrIEq(argv[1], L"--purge")));
    if (StrIEq(cmd, L"import") && argc >= 2) return CmdImport(argc - 1, argv + 1);
    if (StrIEq(cmd, L"remove") && argc == 2) return CmdRemove(argv[1]);
    if (StrIEq(cmd, L"setconfig") && argc == 2) return CmdSetConfig(argv[1]);
    if (StrIEq(cmd, L"status"))    return CmdStatus();
    if (StrIEq(cmd, L"check"))     return CmdCheck();
    if (StrIEq(cmd, L"reload"))    return CmdReload();
    if (StrIEq(cmd, L"disconnect")) return PipeCommand(L"disconnect");
    if (StrIEq(cmd, L"auto"))      return PipeCommand(L"auto");
    if (StrIEq(cmd, L"resume"))    return PipeCommand(L"resume");
    if ((StrIEq(cmd, L"connect") || StrIEq(cmd, L"pause")) && argc == 2) {
        wchar_t req[64];
        swprintf_s(req, _countof(req), L"%ls\t%ls", StrIEq(cmd, L"connect") ? L"connect" : L"pause", argv[1]);
        return PipeCommand(req);
    }
    Usage();
    return 2;
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc >= 2 && StrIEq(argv[1], L"service")) return RunService();

    int first = 1;
    if (argc >= 2 && StrIEq(argv[1], L"--gui")) { g_guiMode = true; first = 2; }
    if (!g_guiMode) {
        _setmode(_fileno(stdout), _O_U16TEXT);
        _setmode(_fileno(stderr), _O_U16TEXT);
    }
    if (!InitPaths(g_paths)) {
        Err(L"Umgebungsvariablen ProgramFiles/ProgramData fehlen.\n");
        return 1;
    }
    const int rc = Dispatch(argc - first, argv + first);

    if (g_guiMode) {
        // Aufruf aus der Oberflaeche: nur bei Fehlern oder Warnungen ein Meldungsfenster.
        if (rc != 0 || wcsstr(g_guiOut, L"WARNUNG"))
            MessageBoxW(nullptr, g_guiOut[0] ? g_guiOut : L"Unbekannter Fehler.", L"WG-AutoSwitch",
                        MB_OK | MB_SETFOREGROUND | (rc != 0 ? MB_ICONERROR : MB_ICONWARNING));
    } else if (OwnsConsole()) {
        Out(L"\nTaste druecken zum Schliessen ...");
        _getwch();
    }
    return rc;
}
