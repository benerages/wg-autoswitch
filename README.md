# WG-AutoSwitch 1.1

Nativer WireGuard-Client-Aufsatz für Windows 11 ARM64 (Snapdragon/Surface, läuft auch auf x64), angelehnt an [WG Tunnel](https://github.com/wgtunnel/desktop). Ein Dienst startet mit Windows und schaltet je nach Netz den passenden WireGuard-Tunnel ein, um oder aus. Eine Tray-Oberfläche zeigt den Zustand und verwaltet Tunnel und Regeln.

| Datei | Rolle |
|---|---|
| `wgas.exe` | Windows-Dienst (virtuelles Konto, ereignisgesteuert) und Kommandozeile |
| `wgas-gui.exe` | Tray und Fenster ohne Adminrechte; für Schlüssel und Regeln fragt sie per UAC |
| WireGuard für Windows | offizielle Installation (ARM64-MSI): Treiber und Tunnel-Dienste |

## Funktionen (Stufe 1)

**Tunnel**
- Liste aller Tunnel mit Status und empfangenen/gesendeten Daten
- Verbinden und Trennen per Klick, Doppelklick oder Tray-Menü
- Import aus Datei (OPNsense-Peer-Generator) oder Zwischenablage, Bearbeiten im eingebauten Editor, Entfernen
- Private Schlüssel liegen nur in `%ProgramData%\WgAutoSwitch\tunnels` (SYSTEM und Administratoren). Nach dem Import aus der Zwischenablage wird sie geleert; die Quelldatei kann der Editor sicher löschen.

**Auto-Tunneling**
- Zeigt das aktuelle Netz: Typ, SSID, BSSID, Gateway-MAC, DNS-Suffix, passende Regel, Konnektivität
- «Als vertraut speichern» und «Tunnel zuordnen» legen mit einem Klick eine Regel aus dem aktuellen Netz an
- Regelliste mit Reihenfolge (erste passende gewinnt); Standardtunnel für unbekannte Netze
- Optionen: Tunnel ohne Netz, Captive Portal abwarten, Entprellung
- Manuelles Schalten gilt bis zum nächsten echten Netzwechsel. WLAN-Roaming zwischen Access Points zählt nicht als Wechsel.
- Pausieren für 15 Minuten, 1 Stunde oder 8 Stunden

**Tray**
- Farbiger Punkt: grün mit weissem Kern = Tunnel aktiv, grau = kein Tunnel (vertrautes Netz), orange = pausiert/manuell/Captive Portal, rot = Dienst nicht erreichbar
- Menü: Tunnel wählen, Trennen, Automatik fortsetzen oder pausieren, Öffnen, Autostart, Beenden
- Startet beim Anmelden mit; abschaltbar im Tray-Menü

Bewusst nicht enthalten: AmneziaWG und Proxy-Modus (brauchen eine eigene WireGuard-Implementierung). Netze nur nach Typ oder WLAN-Name als vertraut einzustufen ist ebenfalls nicht möglich.

**Geplant (Stufe 2):** Kill-Switch über die Windows-Firewall (WFP) mit LAN-Ausnahme, Split-DNS (NRPT), DNS-over-HTTPS.

## Entscheidungsregeln

| Situation | Ergebnis |
|---|---|
| Netz passt auf Regel «kein Tunnel» | kein Tunnel |
| Netz passt auf Regel mit Tunnel X | Tunnel X |
| unbekanntes Netz, Handy-Hotspot, Mobilfunk | Standardtunnel |
| kein Netz | kein Tunnel (spart Akku), ausser «Ohne Netz Tunnel an» |
| LAN und WLAN gleichzeitig | kein Tunnel nur, wenn **alle** Netze «kein Tunnel» ergeben; bei Konflikt Standardtunnel |
| Zustand unklar, Konfiguration ungültig oder Dateirechte unsicher | Fail-safe: Standardtunnel an |
| Captive Portal (Hotel, Zug) | Tunnel wartet, bis Windows Internetzugang meldet |
| Start scheitert | ein Eintrag im Ereignisprotokoll, neue Versuche nach 30 s, 2 min und 10 min |

Ein **vertrautes Netz** (kein Tunnel) braucht die Gateway-MAC plus DNS-Suffix, SSID oder BSSID. Eine SSID allein kann jeder fälschen.

## 1. Bauen

Voraussetzung: [Build Tools für Visual Studio 2022](https://visualstudio.microsoft.com/de/downloads/#build-tools-for-visual-studio-2022) mit «Desktopentwicklung mit C++», «MSVC ARM64-Buildtools» und Windows 11 SDK (10.0.22621 oder neuer).

```bat
build.cmd test      & rem Unit-Tests der Entscheidungslogik
build.cmd           & rem -> build\arm64\wgas.exe und build\arm64\wgas-gui.exe
```

Läuft `wgas-gui.exe` noch, kann der Linker sie nicht überschreiben. Vor dem Neubauen im Tray **Beenden** wählen. Optional signiert `set WGAS_SIGN_THUMB=<Fingerabdruck>` beide Programme.

## 2. Installieren

1. WireGuard für Windows (ARM64-MSI) von <https://www.wireguard.com/install/> installieren. Tunnel **nicht** in der WireGuard-Oberfläche anlegen.
2. `build\arm64\wgas-gui.exe` per Doppelklick starten und **Dienst installieren …** klicken (UAC). Das kopiert beide Programme nach `%ProgramFiles%\WgAutoSwitch\` und richtet den Dienst ein. Danach die Oberfläche einmal über das Tray-Menü beenden und aus `%ProgramFiles%\WgAutoSwitch\wgas-gui.exe` neu starten; der Autostart zeigt bereits dorthin.
3. Reiter **Tunnel** → **Importieren …** (die .conf aus OPNsense: VPN › WireGuard › Peer generator) oder **Aus Zwischenablage …**
4. Reiter **Auto-Tunneling** → zu Hause **Als vertraut speichern …**, dann **Übernehmen (Admin)**

## Kommandozeile

| Befehl | Zweck |
|---|---|
| `wgas install` / `uninstall [/purge]` | Dienst einrichten bzw. entfernen (Admin); `/purge` löscht auch Tunnel und Konfiguration |
| `wgas import <a.conf> [...]` / `remove <tunnel>` | Tunnel verwalten (Admin) |
| `wgas status` | Zustand, Netze, Soll-Zustand |
| `wgas check` / `reload` | Konfiguration prüfen bzw. übernehmen (Admin) |
| `wgas connect <tunnel>` / `disconnect` / `auto` | manuell schalten bzw. Automatik fortsetzen |
| `wgas pause <min>` / `resume` | Automatik anhalten bzw. fortsetzen |

Protokoll: Ereignisanzeige › Windows-Protokolle › Anwendung, Quelle `WgAutoSwitch`. Es werden nur Zustandswechsel und Fehler protokolliert.

## Sicherheit

- Dienst als `NT SERVICE\WgAutoSwitch` mit nur `SeChangeNotifyPrivilege` und `SeCreateGlobalPrivilege` (für das Zustandssignal an die Oberfläche). Auf den Tunnel-Diensten hat er nur Start, Stop und Status.
- Named Pipe `\\.\pipe\WgAutoSwitch`: nur lokal, Netzwerkanmeldungen verweigert; Zugriff nur für SYSTEM, Administratoren und interaktiv angemeldete Benutzer. Darüber gehen nur Status, Verbinden, Trennen und Pausieren. Konfiguration und Schlüssel ändern ausschliesslich Administratoren.
- Die Oberfläche prüft, dass der Pipe-Server wirklich der Dienst ist (Prozess-ID), und verbindet sich nur mit Identifikationsstufe.
- Kein offener Port, keine Telemetrie, kein Auto-Update.
- `config.ini` gehört Administratoren, der Dienst darf nur lesen. Bei unsicheren Rechten greift der Fail-safe.
- Kill-Switch bis Stufe 2: In der .conf `AllowedIPs = 0.0.0.0/0, ::/0` verwenden. WireGuard für Windows blockiert dann ungetunnelten Verkehr, solange der Tunnel läuft.

## Bekannte Grenzen

- **SSID/BSSID unter Windows 11 24H2+:** Möglicherweise nur mit aktivierten Standortdiensten lesbar. Fehlen sie, gilt das WLAN als unbekannt (Fail-safe); Regeln funktionieren dann weiter mit Gateway-MAC plus DNS-Suffix.
- **Handshake-Zeit:** Die offizielle WireGuard-Installation gibt sie nur an Administratoren heraus. Die Oberfläche zeigt stattdessen die Datenzähler des Tunneladapters.
- **Datenzähler:** Bei sichtbarem Fenster aktualisieren sie sich alle 2 Sekunden. Im Tray gibt es keinen Timer, die Oberfläche wartet nur auf das Signal des Dienstes.
- Abnahme-Messungen (WPR, `powercfg /sleepstudy`, Grösse, Working Set) stehen noch aus.

## Aufbau

```
src/decide.h     Entscheidungslogik (ohne Windows, Unit-Tests in tests/)
src/common.*     Pfade, Konfiguration lesen/schreiben, Netzmerkmale, Tunnel-Dienste, Pipe-Client
src/wgas.cpp     Dienst (Ereignisschleife, Pipe-Server) + Kommandozeile
src/gui.cpp      Tray, Fenster, Regel-Editor, Tunnel-Editor (Admin-Modus)
```
