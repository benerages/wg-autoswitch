#pragma once
// update.h - Update-Pruefung und -Download fuer wgas-gui.exe.
//
// Ablauf (nur Oberflaeche, Benutzerkontext, eigener Thread):
//   1. CheckLatest: GET https://api.github.com/repos/<repo>/releases/latest (WinHTTP, nur HTTPS).
//   2. DownloadUpdate: Paket fuer die native Architektur + SHA256SUMS.txt laden,
//      SHA-256 pruefen, mit dem Windows-eigenen tar.exe entpacken, Signatur vorpruefen.
//   3. Installation: "wgas.exe --gui update <ordner>" aus %ProgramFiles% per UAC. Der
//      Admin-Prozess kopiert die Dateien in einen geschuetzten Ordner und prueft Signatur,
//      Herausgeber und Version dort ERNEUT, bevor er etwas ersetzt (siehe wgas.cpp, CmdUpdate).

#include "common.h"

namespace wgas {

struct UpdateInfo {
    bool     available;          // neuere Version gefunden
    unsigned version[3];
    wchar_t  tag[32];
    wchar_t  pageUrl[256];       // Release-Seite auf GitHub
    wchar_t  zipUrl[512];
    wchar_t  zipName[128];
    wchar_t  sumsUrl[512];
    wchar_t  notes[1200];        // Anfang der Release-Beschreibung
};

constexpr DWORD kUpdateUnsigned = 0xE0010001;   // eigener Fehlercode: Paket nicht (korrekt) signiert

// Blockierend (eigener Thread). 0 = Abfrage erfolgreich (u.available sagt, ob neuer).
DWORD CheckLatest(UpdateInfo& u);

// Blockierend. Bei Erfolg steht in dir der Ordner mit wgas.exe und wgas-gui.exe.
// msg erhaelt eine lesbare Begruendung bei Fehlern; signer den gefundenen Herausgeber.
DWORD DownloadUpdate(const UpdateInfo& u, wchar_t* dir, size_t dirCap, wchar_t* msg, size_t msgCap,
                     wchar_t* signer, size_t signerCap);

// true, wenn url zur Release-Seite dieses Projekts gehoert (vor dem Oeffnen im Browser pruefen).
bool IsProjectUrl(const wchar_t* url);

} // namespace wgas
