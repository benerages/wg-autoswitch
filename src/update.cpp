// update.cpp - Update-Pruefung und -Download (siehe update.h).
// Abhaengigkeiten: winhttp (HTTPS), bcrypt/wintrust ueber common.cpp; tar.exe ist Teil von Windows 10/11.
#include "update.h"
#include <winhttp.h>

#pragma comment(lib, "winhttp.lib")

namespace wgas {

namespace {

constexpr DWORD kMaxApiBytes = 512 * 1024;
constexpr DWORD kMaxZipBytes = 8 * 1024 * 1024;

// ---------------------------------------------------------------- HTTPS-Abruf

// Nur HTTPS und nur GitHub-Hosts. Weiterleitungen (zu den GitHub-Downloadservern) folgt
// WinHTTP selbst; von HTTPS zu HTTP leitet es standardmaessig nicht weiter.
bool AllowedHost(const wchar_t* host) {
    return StrIEq(host, L"api.github.com") || StrIEq(host, L"github.com");
}

DWORD HttpGet(const wchar_t* url, DWORD maxBytes, BYTE** data, DWORD* size) {
    *data = nullptr;
    *size = 0;
    wchar_t host[256], path[2048];
    URL_COMPONENTS uc;
    ZeroMemory(&uc, sizeof uc);
    uc.dwStructSize = sizeof uc;
    uc.lpszHostName = host;
    uc.dwHostNameLength = static_cast<DWORD>(_countof(host));
    uc.lpszUrlPath = path;
    uc.dwUrlPathLength = static_cast<DWORD>(_countof(path));
    if (!WinHttpCrackUrl(url, 0, 0, &uc)) return GetLastError();
    if (uc.nScheme != INTERNET_SCHEME_HTTPS || !AllowedHost(host)) return ERROR_ACCESS_DENIED;

    wchar_t agent[64];
    swprintf_s(agent, _countof(agent), L"WG-AutoSwitch/%ls", WGAS_VERSION_WSTR);
    HINTERNET session = WinHttpOpen(agent, WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME,
                                    WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) return GetLastError();
    WinHttpSetTimeouts(session, 10000, 10000, 15000, 30000);
    DWORD err = NO_ERROR;
    HINTERNET conn = WinHttpConnect(session, host, uc.nPort, 0);
    HINTERNET req = conn ? WinHttpOpenRequest(conn, L"GET", path, nullptr, WINHTTP_NO_REFERER,
                                              WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE)
                         : nullptr;
    if (!req) err = GetLastError();
    if (!err && !WinHttpSendRequest(req, L"Accept: application/vnd.github+json\r\n", static_cast<DWORD>(-1L),
                                    WINHTTP_NO_REQUEST_DATA, 0, 0, 0))
        err = GetLastError();
    if (!err && !WinHttpReceiveResponse(req, nullptr)) err = GetLastError();
    DWORD status = 0, len = sizeof status;
    if (!err && !WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX,
                                     &status, &len, WINHTTP_NO_HEADER_INDEX))
        err = GetLastError();
    if (!err && status != 200) err = 0xE0020000 | (status & 0xFFFF);   // HTTP-Status im Fehlercode

    HANDLE heap = GetProcessHeap();
    BYTE* buf = nullptr;
    DWORD used = 0, cap = 0;
    while (!err) {
        DWORD avail = 0;
        if (!WinHttpQueryDataAvailable(req, &avail)) { err = GetLastError(); break; }
        if (!avail) break;
        if (used + avail > maxBytes) { err = ERROR_FILE_TOO_LARGE; break; }
        if (used + avail + 1 > cap) {
            cap = (used + avail + 1) * 2 > maxBytes + 1 ? maxBytes + 1 : (used + avail + 1) * 2;
            BYTE* nb = static_cast<BYTE*>(buf ? HeapReAlloc(heap, 0, buf, cap) : HeapAlloc(heap, 0, cap));
            if (!nb) { err = ERROR_NOT_ENOUGH_MEMORY; break; }
            buf = nb;
        }
        DWORD got = 0;
        if (!WinHttpReadData(req, buf + used, avail, &got)) { err = GetLastError(); break; }
        used += got;
    }
    if (req) WinHttpCloseHandle(req);
    if (conn) WinHttpCloseHandle(conn);
    WinHttpCloseHandle(session);
    if (err) {
        if (buf) HeapFree(heap, 0, buf);
        return err;
    }
    if (!buf) { buf = static_cast<BYTE*>(HeapAlloc(heap, 0, 1)); if (!buf) return ERROR_NOT_ENOUGH_MEMORY; }
    buf[used] = 0;   // fuer Textauswertung
    *data = buf;
    *size = used;
    return NO_ERROR;
}

// ---------------------------------------------------------------- minimale JSON-Auswertung
// Sucht ab pos den naechsten Schluessel "key" mit Zeichenkettenwert und dekodiert ihn
// (UTF-8, Escapes inkl. \uXXXX) nach out. Liefert die Position nach dem Wert oder 0.

void AppendUtf8(char* out, size_t cap, size_t& o, unsigned cp) {
    if (cp < 0x80) { if (o + 1 < cap) out[o++] = static_cast<char>(cp); }
    else if (cp < 0x800) { if (o + 2 < cap) { out[o++] = static_cast<char>(0xC0 | (cp >> 6)); out[o++] = static_cast<char>(0x80 | (cp & 0x3F)); } }
    else { if (o + 3 < cap) { out[o++] = static_cast<char>(0xE0 | (cp >> 12)); out[o++] = static_cast<char>(0x80 | ((cp >> 6) & 0x3F)); out[o++] = static_cast<char>(0x80 | (cp & 0x3F)); } }
}

size_t JsonString(const char* js, size_t len, size_t pos, const char* key, wchar_t* out, size_t cap) {
    out[0] = 0;
    char pattern[64];
    sprintf_s(pattern, sizeof pattern, "\"%s\"", key);
    const size_t pl = strlen(pattern);
    for (size_t i = pos; i + pl < len; ++i) {
        if (memcmp(js + i, pattern, pl) != 0) continue;
        size_t p = i + pl;
        while (p < len && (js[p] == ' ' || js[p] == '\t' || js[p] == '\r' || js[p] == '\n')) ++p;
        if (p >= len || js[p] != ':') continue;
        ++p;
        while (p < len && (js[p] == ' ' || js[p] == '\t' || js[p] == '\r' || js[p] == '\n')) ++p;
        if (p >= len || js[p] != '"') continue;   // kein Zeichenkettenwert (z. B. null)
        ++p;
        static char tmp[8192];
        size_t o = 0;
        while (p < len && js[p] != '"') {
            char c = js[p++];
            if (c == '\\' && p < len) {
                const char e = js[p++];
                switch (e) {
                case 'n': c = '\n'; break;
                case 'r': c = '\r'; break;
                case 't': c = '\t'; break;
                case 'b': case 'f': c = ' '; break;
                case 'u': {
                    unsigned cp = 0;
                    for (int k = 0; k < 4 && p < len; ++k, ++p) {
                        const char h = js[p];
                        cp = cp * 16 + static_cast<unsigned>(h >= '0' && h <= '9' ? h - '0' : h >= 'a' && h <= 'f' ? h - 'a' + 10 : h >= 'A' && h <= 'F' ? h - 'A' + 10 : 0);
                    }
                    if (cp >= 0xD800 && cp <= 0xDFFF) cp = '?';   // Ersatzpaare: hier nicht noetig
                    AppendUtf8(tmp, sizeof tmp, o, cp);
                    continue;
                }
                default: c = e; break;   // \" \\ \/
                }
            }
            if (o + 1 < sizeof tmp) tmp[o++] = c;
        }
        tmp[o] = 0;
        const int n = MultiByteToWideChar(CP_UTF8, 0, tmp, -1, out, static_cast<int>(cap));
        if (n <= 0) out[0] = 0;
        out[cap - 1] = 0;
        return p + 1;
    }
    return 0;
}

bool EndsWithI(const wchar_t* s, const wchar_t* suffix) {
    const int a = StrLen(s), b = StrLen(suffix);
    return a >= b && StrIEq(s + a - b, suffix);
}

DWORD WriteFileAll(const wchar_t* path, const BYTE* data, DWORD size) {
    HANDLE f = CreateFileW(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return GetLastError();
    DWORD w = 0;
    const BOOL ok = WriteFile(f, data, size, &w, nullptr) && w == size;
    const DWORD e = ok ? NO_ERROR : GetLastError();
    CloseHandle(f);
    return e;
}

DWORD RunAndWait(wchar_t* cmd, const wchar_t* exe) {
    STARTUPINFOW si;
    ZeroMemory(&si, sizeof si);
    si.cb = sizeof si;
    PROCESS_INFORMATION pi;
    if (!CreateProcessW(exe, cmd, nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) return GetLastError();
    DWORD code = ERROR_TIMEOUT;
    if (WaitForSingleObject(pi.hProcess, 60000) == WAIT_OBJECT_0) GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return code;
}

} // namespace

bool IsProjectUrl(const wchar_t* url) {
    wchar_t prefix[160];
    swprintf_s(prefix, _countof(prefix), L"https://github.com/%ls/", WGAS_REPO_WSTR);
    return StartsWithI(url, prefix);
}

DWORD CheckLatest(UpdateInfo& u) {
    ZeroBytes(&u, sizeof u);
    wchar_t url[256];
    swprintf_s(url, _countof(url), L"https://api.github.com/repos/%ls/releases/latest", WGAS_REPO_WSTR);
    BYTE* data = nullptr;
    DWORD size = 0;
    const DWORD e = HttpGet(url, kMaxApiBytes, &data, &size);
    if (e) return e;
    const char* js = reinterpret_cast<const char*>(data);

    JsonString(js, size, 0, "tag_name", u.tag, _countof(u.tag));
    JsonString(js, size, 0, "html_url", u.pageUrl, _countof(u.pageUrl));
    JsonString(js, size, 0, "body", u.notes, _countof(u.notes));
    if (!IsProjectUrl(u.pageUrl)) u.pageUrl[0] = 0;

    // Passendes Paket und Pruefsummen unter den Release-Dateien suchen.
    wchar_t arch[32], prefix[200];
    swprintf_s(arch, _countof(arch), L"-windows-%ls.zip", NativeArch());
    swprintf_s(prefix, _countof(prefix), L"https://github.com/%ls/releases/download/", WGAS_REPO_WSTR);
    wchar_t asset[512];
    size_t pos = 0;
    while ((pos = JsonString(js, size, pos, "browser_download_url", asset, _countof(asset))) != 0) {
        if (!StartsWithI(asset, prefix)) continue;
        if (EndsWithI(asset, arch)) {
            StrCopy(u.zipUrl, 512, asset);
            const wchar_t* slash = wcsrchr(asset, L'/');
            StrCopy(u.zipName, 128, slash ? slash + 1 : asset);
        } else if (EndsWithI(asset, L"/SHA256SUMS.txt")) {
            StrCopy(u.sumsUrl, 512, asset);
        }
    }
    HeapFree(GetProcessHeap(), 0, data);

    if (!ParseVersion(u.tag, u.version)) return ERROR_INVALID_DATA;
    unsigned cur[3];
    CurrentVersion(cur);
    u.available = CompareVersion(u.version, cur) > 0;
    return NO_ERROR;
}

DWORD DownloadUpdate(const UpdateInfo& u, wchar_t* dir, size_t dirCap, wchar_t* msg, size_t msgCap,
                     wchar_t* signer, size_t signerCap) {
    msg[0] = dir[0] = signer[0] = 0;
    if (!u.zipUrl[0] || !u.sumsUrl[0]) {
        swprintf_s(msg, msgCap, T(L"Das Release enthält kein Paket für diese Architektur (%ls)."), NativeArch());
        return ERROR_FILE_NOT_FOUND;
    }
    // Arbeitsordner im Benutzer-Temp (nur fuer den Benutzer, SYSTEM und Admins zugaenglich).
    wchar_t temp[MAX_PATH], base[MAX_PATH], zip[MAX_PATH], pkg[MAX_PATH];
    if (!GetTempPathW(MAX_PATH, temp)) return GetLastError();
    swprintf_s(base, _countof(base), L"%lswgas-update-%u.%u.%u", temp, u.version[0], u.version[1], u.version[2]);
    swprintf_s(zip, _countof(zip), L"%ls\\%ls", base, u.zipName);
    swprintf_s(pkg, _countof(pkg), L"%ls\\pkg", base);
    CreateDirectoryW(base, nullptr);
    CreateDirectoryW(pkg, nullptr);

    // 1. Pruefsummen und Paket laden
    BYTE* sums = nullptr;
    DWORD sumsSize = 0;
    DWORD e = HttpGet(u.sumsUrl, 64 * 1024, &sums, &sumsSize);
    BYTE* data = nullptr;
    DWORD size = 0;
    if (!e) e = HttpGet(u.zipUrl, kMaxZipBytes, &data, &size);
    if (!e) e = WriteFileAll(zip, data, size);
    if (data) HeapFree(GetProcessHeap(), 0, data);
    if (e) {
        if (sums) HeapFree(GetProcessHeap(), 0, sums);
        swprintf_s(msg, msgCap, T(L"Download fehlgeschlagen (Fehler %lu)."), e);
        return e;
    }

    // 2. SHA-256 gegen die Zeile "<hash>  <zipName>" in SHA256SUMS.txt
    wchar_t actual[80];
    char want[65] = "";
    char nameA[128];
    WideCharToMultiByte(CP_UTF8, 0, u.zipName, -1, nameA, sizeof nameA, nullptr, nullptr);
    const char* text = reinterpret_cast<const char*>(sums);
    for (const char* line = text; *line;) {
        const char* end = line;
        while (*end && *end != '\n') ++end;
        const char* sp = line;
        while (sp < end && *sp != ' ') ++sp;
        const char* name = sp;
        while (name < end && *name == ' ') ++name;
        size_t nl = static_cast<size_t>(end - name);
        while (nl && (name[nl - 1] == '\r' || name[nl - 1] == ' ')) --nl;
        if (sp - line == 64 && nl == strlen(nameA) && memcmp(name, nameA, nl) == 0) {
            memcpy(want, line, 64);
            want[64] = 0;
        }
        line = *end ? end + 1 : end;
    }
    HeapFree(GetProcessHeap(), 0, sums);
    wchar_t wantW[80];
    MultiByteToWideChar(CP_UTF8, 0, want, -1, wantW, 80);
    if (!want[0] || !Sha256File(zip, actual, _countof(actual)) || !StrIEq(actual, wantW)) {
        swprintf_s(msg, msgCap, L"%ls", T(L"SHA-256-Prüfsumme stimmt nicht überein."));
        return ERROR_INVALID_DATA;
    }

    // 3. Entpacken mit tar.exe (Windows 10 1803+); keine weitere Bibliothek noetig.
    wchar_t tar[MAX_PATH], cmd[MAX_PATH * 3];
    ExpandEnvironmentStringsW(L"%SystemRoot%\\System32\\tar.exe", tar, MAX_PATH);
    swprintf_s(cmd, _countof(cmd), L"\"%ls\" -xf \"%ls\" -C \"%ls\"", tar, zip, pkg);
    wchar_t exe[MAX_PATH], gui[MAX_PATH];
    swprintf_s(exe, _countof(exe), L"%ls\\wgas.exe", pkg);
    swprintf_s(gui, _countof(gui), L"%ls\\wgas-gui.exe", pkg);
    if (RunAndWait(cmd, tar) != 0 || !FileExists(exe) || !FileExists(gui)) {
        swprintf_s(msg, msgCap, L"%ls", T(L"Entpacken fehlgeschlagen."));
        return ERROR_INVALID_DATA;
    }

    // 4. Signatur vorpruefen (der Admin-Prozess prueft spaeter nochmals verbindlich).
    if (VerifyPublisher(exe, WGAS_PUBLISHER_WSTR, signer, signerCap) != NO_ERROR ||
        VerifyPublisher(gui, WGAS_PUBLISHER_WSTR, signer, signerCap) != NO_ERROR)
        return kUpdateUnsigned;

    swprintf_s(dir, dirCap, L"%ls", pkg);
    return NO_ERROR;
}

} // namespace wgas
