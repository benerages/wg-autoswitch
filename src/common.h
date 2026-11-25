#pragma once
// common.h - gemeinsamer Code von wgas.exe (Dienst + CLI) und wgas-gui.exe.
//
// Abhaengigkeiten (nur Windows-DLLs): kernel32, advapi32 (Dienste, ACL, Registry),
// iphlpapi (Netzmerkmale), wlanapi (SSID/BSSID).

#ifndef UNICODE
#  define UNICODE
#endif
#ifndef _UNICODE
#  define _UNICODE
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2ipdef.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <wlanapi.h>
#include <aclapi.h>
#include <sddl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#include "decide.h"

namespace wgas {

// ------------------------------------------------------------------ Namen
inline constexpr wchar_t kSvcName[]      = L"WgAutoSwitch";
inline constexpr wchar_t kSvcDisplay[]   = L"WG-AutoSwitch";
inline constexpr wchar_t kSvcAccount[]   = L"NT SERVICE\\WgAutoSwitch";
inline constexpr wchar_t kRegKey[]       = L"SOFTWARE\\WgAutoSwitch";
inline constexpr wchar_t kTunnelPrefix[] = L"WireGuardTunnel$";
inline constexpr wchar_t kPipeName[]     = L"\\\\.\\pipe\\WgAutoSwitch";
inline constexpr wchar_t kStateEvent[]   = L"Global\\WgAutoSwitchState";  // Signal "Zustand geaendert"

constexpr int   kMaxKnown     = 32;      // Tunnel-Dienste insgesamt (Konfiguration + installiert)
constexpr DWORD kPipeReqChars = 512;     // Anfrage an den Dienst (Zeichen)
constexpr DWORD kPipeRspChars = 32768;   // Antwort des Dienstes (Zeichen)

// ------------------------------------------------------------------ Pfade
struct Paths {
    wchar_t progDir[MAX_PATH];
    wchar_t exe[MAX_PATH];        // %ProgramFiles%\WgAutoSwitch\wgas.exe
    wchar_t guiExe[MAX_PATH];     // %ProgramFiles%\WgAutoSwitch\wgas-gui.exe
    wchar_t dataDir[MAX_PATH];
    wchar_t cfg[MAX_PATH];
    wchar_t tunDir[MAX_PATH];
    wchar_t wgExe[MAX_PATH];      // offizielle WireGuard-Installation
};
extern Paths g_paths;
bool InitPaths(Paths& p);

// ------------------------------------------------------------------ Text
void Appendf(wchar_t* buf, size_t cap, const wchar_t* fmt, ...);
void MacToStr(const unsigned char* m, wchar_t* out, size_t cap);
void SanitizeField(const wchar_t* in, wchar_t* out, size_t cap);   // Tab/Zeilenumbruch -> '?'
wchar_t* NextField(wchar_t*& p);                                    // Tab-getrennt, zerlegt in place
const wchar_t* KindName(IfKind k);    // Anzeige: LAN, WLAN, ...
const wchar_t* KindKey(IfKind k);     // config.ini: ethernet, wifi, ...
const wchar_t* ConnName(Connectivity c);
bool ParseKind(const wchar_t* s, IfKind& k);
const wchar_t* TunnelLabel(const Config& c, int idx);
bool FileExists(const wchar_t* path);
ULONGLONG NowFileTime();
void FormatLocalTime(ULONGLONG t, wchar_t* out, size_t cap);
void FormatBytes(ULONG64 v, wchar_t* out, size_t cap);

// ------------------------------------------------------------------ Registry
bool RegWrite(const wchar_t* name, DWORD type, const void* data, DWORD bytes);
bool RegReadFailsafe(wchar_t* out, DWORD cap);
void RegWriteFailsafe(const wchar_t* name);

// ------------------------------------------------------------------ Konfiguration
bool LoadConfig(const wchar_t* path, Config& c, wchar_t* err, size_t errCap);
void BuildFailsafeConfig(Config& c);
int  AddTunnel(Config& c, const wchar_t* name);
// Serialisiert c als config.ini-Text. false, wenn ein Wert nicht darstellbar ist.
bool WriteConfigText(const Config& c, wchar_t* out, size_t cap);
bool WriteUtf16File(const wchar_t* path, const wchar_t* text, bool createNew);

// ------------------------------------------------------------------ Dateirechte
bool IsSecureObject(const wchar_t* path);
bool ConfigIsSecure(const Paths& p, wchar_t* err, size_t errCap);
bool ApplySddl(const wchar_t* path, const wchar_t* sddl);
bool GetServiceSidString(wchar_t* out, size_t cap);
bool SecureDataDir(const Paths& p, const wchar_t* svcSid);

// ------------------------------------------------------------------ Netz
struct Snapshot {
    bool   ok;
    int    n;
    IfInfo ifs[kMaxIfs];
};
bool CollectInterfaces(const Config* cfg, Snapshot& s);
Connectivity QueryConnectivity();

// ------------------------------------------------------------------ Tunnel-Dienste
enum class TState { Missing, Stopped, StartPending, Running, StopPending, Error };

struct KnownTunnels {
    int     n;
    wchar_t names[kMaxKnown][kNameLen];
};

void   TunnelSvcName(const wchar_t* tunnel, wchar_t* out, size_t cap);
TState QueryTunnel(SC_HANDLE scm, const wchar_t* tunnel);
DWORD  StopTunnel(SC_HANDLE scm, const wchar_t* tunnel);
DWORD  StartTunnel(SC_HANDLE scm, const wchar_t* tunnel);
void   WaitWhile(SC_HANDLE h, DWORD pendingState, DWORD timeoutMs);
// Tunnel aus der Konfiguration plus alle installierten WireGuardTunnel$*-Dienste.
void   EnumTunnels(SC_HANDLE scm, const Config* cfg, KnownTunnels& k);
int    FindKnown(const KnownTunnels& k, const wchar_t* name);
// Empfangene/gesendete Bytes des WireGuard-Adapters (Alias = Tunnelname).
bool   TunnelTraffic(const wchar_t* tunnel, ULONG64& rx, ULONG64& tx);
DWORD  ServiceProcessId();   // 0 = Dienst laeuft nicht

// ------------------------------------------------------------------ Named Pipe (Client)
// Sendet eine Anfrage an den Dienst. Prueft, dass der Pipe-Server wirklich der
// Dienst WgAutoSwitch ist (Schutz vor vorgetaeuschten Pipes). Zeitlimit 5 s.
DWORD PipeTransact(const wchar_t* req, wchar_t* resp, DWORD respChars);

} // namespace wgas
