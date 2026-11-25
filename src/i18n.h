#pragma once
// i18n.h - Zweisprachigkeit (Deutsch/Englisch) ohne Bibliothek.
//
// Texte stehen im Code als deutscher Schluessel: T(L"Verbinden"). Die Tabelle in
// i18n_table.h liefert dazu die angezeigte deutsche (mit Umlauten) und die englische
// Fassung. Fehlt ein Schluessel, wird er unveraendert angezeigt.
//
// Sprache: Benutzerwahl in HKCU\Software\WgAutoSwitch\Language ("de", "en"), sonst die
// Windows-Anzeigesprache (Deutsch -> de, alles andere -> en). Der Dienst verwendet die
// Systemsprache, weil er ohne angemeldeten Benutzer laeuft.

namespace wgas {

enum class Lang { De, En };

// system = true: Systemsprache (Dienst); false: Benutzerwahl bzw. Benutzersprache.
void InitLanguage(bool system);
Lang CurrentLanguage();

// Gespeicherte Benutzerwahl: nullptr = automatisch, sonst L"de" oder L"en".
const wchar_t* LanguageOverride();
bool SetLanguageOverride(const wchar_t* code);

const wchar_t* T(const wchar_t* key);

} // namespace wgas
