// test_i18n.cpp - prueft die Uebersetzungstabelle (ohne Windows-APIs).
//   * Platzhalter (%ls, %lu, %d, ...) muessen in Schluessel, Deutsch und Englisch
//     in derselben Reihenfolge vorkommen - sonst liest swprintf falsche Argumente.
//   * Schluessel eindeutig, keine leeren Texte.
// Windows:  build.cmd test      Linux:  g++ -std=c++20 tests/test_i18n.cpp -o t && ./t
#include "../src/i18n_table.h"
#include <cstdio>
#include <cwchar>

using namespace wgas;

// Extrahiert die Folge der Platzhalter als Text, z. B. "ls|lu|ls|".
static void Specs(const wchar_t* s, wchar_t* out, int cap) {
    int o = 0;
    out[0] = 0;
    for (const wchar_t* p = s; *p; ++p) {
        if (*p != L'%') continue;
        ++p;
        if (*p == L'%') continue;   // "%%"
        while (*p == L'-' || *p == L'+' || *p == L' ' || *p == L'#' || *p == L'0') ++p;
        while ((*p >= L'0' && *p <= L'9') || *p == L'.') ++p;
        while ((*p == L'l' || *p == L'h' || *p == L'L') && o < cap - 2) out[o++] = *p++;
        if (!*p) break;
        if (o < cap - 2) { out[o++] = *p; out[o++] = L'|'; }
        out[o] = 0;
    }
}

int main() {
    int fails = 0, n = 0;
    for (const TrEntry& e : kTrTable) {
        ++n;
        wchar_t k[64], d[64], en[64];
        Specs(e.key, k, 64);
        Specs(e.de ? e.de : e.key, d, 64);
        Specs(e.en, en, 64);
        if (std::wcscmp(k, d) != 0 || std::wcscmp(k, en) != 0) {
            std::printf("FEHLER Platzhalter: %ls\n  de: %ls\n  en: %ls\n", e.key, e.de ? e.de : e.key, e.en);
            ++fails;
        }
        if (!e.key[0] || !e.en[0] || (e.de && !e.de[0])) { std::printf("FEHLER leer: %ls\n", e.key); ++fails; }
        for (const TrEntry& o : kTrTable)
            if (&o != &e && std::wcscmp(o.key, e.key) == 0) { std::printf("FEHLER doppelt: %ls\n", e.key); ++fails; break; }
    }
    std::printf("%d Uebersetzungen, %d Fehler\n", n, fails);
    return fails ? 1 : 0;
}
