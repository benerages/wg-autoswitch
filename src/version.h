#ifndef WGAS_VERSION_H
#define WGAS_VERSION_H
// version.h - einzige Quelle der Versionsnummer (Code, Ressourcen, Release-Pruefung im Workflow).
// Fuer ein Release: Nummer hier erhoehen, committen, Tag "v<Nummer>" pushen.
// Auch von rc.exe gelesen: nur #define, keine C++-Syntax.

#define WGAS_VERSION_MAJOR 1
#define WGAS_VERSION_MINOR 3
#define WGAS_VERSION_PATCH 1
#define WGAS_VERSION_STR   "1.3.1"
#define WGAS_VERSION_WSTR  L"1.3.1"

// GitHub-Repository fuer die Update-Pruefung und den Download der Releases.
#define WGAS_REPO_WSTR     L"benerages/wg-autoswitch"
// Erwarteter Herausgeber in der Authenticode-Signatur (SignPath Foundation, siehe CODE_SIGNING.md).
#define WGAS_PUBLISHER_WSTR L"SignPath Foundation"

#endif
