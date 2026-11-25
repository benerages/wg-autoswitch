# WG-AutoSwitch

A small native companion for **WireGuard for Windows** that turns your tunnel on and off automatically depending on the network you are connected to. Built for Windows 11 on ARM64 (Snapdragon, Surface), and runs just as well on x64. Inspired by [WG Tunnel](https://github.com/wgtunnel/desktop).

Typical use: at home (trusted network) no tunnel; anywhere else (hotel, train, phone hotspot, office) the tunnel comes up by itself.

> **Written with Claude.** The code, build script and documentation were created together with [Claude](https://claude.ai) (Anthropic), then built and tested on a real Surface (ARM64).

| File | Role |
|---|---|
| `wgas.exe` | Windows service (virtual account, event-driven) and command line |
| `wgas-gui.exe` | Tray icon and window; runs without admin rights and asks via UAC only for keys and rules |
| WireGuard for Windows | The official installation (ARM64 MSI) provides the driver and the tunnel services |

The user interface, command line and event log messages are available in **English and German**. The language follows Windows (German Windows → German, everything else → English) and can be changed in the tray menu under *Language*. The service writes its event log in the system language.

## Download and install

1. Install [WireGuard for Windows](https://www.wireguard.com/install/) (the ARM64 MSI on ARM devices). Do **not** add tunnels in the WireGuard app itself.
2. Download the package for your device from the [latest release](https://github.com/benerages/wg-autoswitch/releases/latest):
   - `wg-autoswitch-<version>-windows-arm64.zip` for Surface and other Snapdragon devices
   - `wg-autoswitch-<version>-windows-x64.zip` for Intel and AMD devices

   Optionally compare the file with `SHA256SUMS.txt` (`Get-FileHash <file>.zip` in PowerShell).
3. Unzip it, start `wgas-gui.exe` and click **Install service …** (UAC prompt). This copies both programs to `%ProgramFiles%\WgAutoSwitch\` and sets up the service, which then starts with Windows before sign-in. Exit the tray app once and start it again from `%ProgramFiles%\WgAutoSwitch\wgas-gui.exe`; the sign-in entry already points there. The unzipped folder can be deleted afterwards.
4. On the **Tunnels** tab, choose **Import …** (a `.conf` file, e.g. from the OPNsense *Peer generator*) or **From clipboard …**.
5. On the **Auto-Tunneling** tab, at home: **Save as trusted …**, then **Apply (admin)**.

Until releases are code-signed, Windows SmartScreen may warn on first start (*More info › Run anyway*); see [Code signing](#code-signing). Each ZIP also contains `INSTALLATION.txt` with these steps in English and German.

### Update

Signed releases can be installed from the tray menu (**Install update …**). Otherwise: exit the tray app, unzip the new release and run in an elevated PowerShell inside that folder:

```powershell
.\wgas.exe install
```

Configuration, rules and tunnels in `%ProgramData%\WgAutoSwitch` are kept.

### Uninstall

In an elevated PowerShell: `& "$env:ProgramFiles\WgAutoSwitch\wgas.exe" uninstall` removes the service and programs (files in use are removed at the next restart) and keeps your tunnels and rules. Add `/purge` to delete those as well. WireGuard for Windows itself stays installed.

### Reinstalling WireGuard

Uninstalling WireGuard removes its tunnel services. Your keys and rules are kept in `%ProgramData%\WgAutoSwitch`. After reinstalling WireGuard, restore all tunnels from an elevated PowerShell:

```powershell
$wgas = "$env:ProgramFiles\WgAutoSwitch\wgas.exe"
Get-ChildItem "$env:ProgramData\WgAutoSwitch\tunnels\*.conf" | ForEach-Object { & $wgas import $_.FullName }
```

Updating WireGuard needs no action.

## Features

**Tunnels**
- List of all tunnels with status and bytes received/sent
- Connect/disconnect by button, double-click or tray menu
- Import from file (e.g. the OPNsense *Peer generator*) or from the clipboard; built-in editor; remove
- Private keys are stored only in `%ProgramData%\WgAutoSwitch\tunnels` (SYSTEM and Administrators). After a clipboard import the clipboard is cleared, and after a file import the editor offers to securely delete the source file.

**Auto-tunneling**
- Shows the current network: type, SSID, BSSID, gateway MAC, DNS suffix, matching rule and connectivity
- *Save as trusted* and *Assign tunnel* create a rule from the current network with one click
- Ordered rule list (first match wins) and a default tunnel for unknown networks
- Options: keep tunnel on without network, wait for captive portal login, debounce time
- Manual switching holds until the next real network change. Roaming between access points of the same Wi-Fi does not count as a change.
- Pause for 15 minutes, 1 hour or 8 hours

**Updates**
- The tray app checks GitHub once a day for a newer release and shows a notification (can be turned off in the tray menu; see [PRIVACY.md](PRIVACY.md)).
- **Install update …** downloads the package for your architecture (ARM64 or x64), verifies the SHA-256 checksum and the Authenticode signature (publisher *SignPath Foundation*), and installs it after one UAC prompt. The elevated installer re-checks the signature, publisher and version in a protected folder and refuses downgrades. Unsigned releases are never installed automatically; for those the release page opens instead.
- The version is shown in the window title, under **About WG-AutoSwitch …** in the tray menu, and with `wgas version`.

**Tray**
- Coloured dot: green with white core = tunnel up, grey = no tunnel (trusted network), orange = paused/manual/captive portal, red = service not reachable
- Menu: pick a tunnel, disconnect, resume or pause automation, language, updates, about, open, start at sign-in, exit
- Starts at sign-in by default (can be turned off in the tray menu)

Intentionally not included: AmneziaWG and proxy mode, which would need a separate WireGuard implementation. A network cannot be trusted by type or Wi-Fi name alone (see *Decision rules*).

## Decision rules

| Situation | Result |
|---|---|
| Network matches a rule with *no tunnel* | no tunnel |
| Network matches a rule with tunnel X | tunnel X |
| Unknown network, phone hotspot, mobile broadband | default tunnel |
| No network | no tunnel (saves battery), unless *keep tunnel on without network* is set |
| Ethernet and Wi-Fi at the same time | no tunnel only if **all** networks say *no tunnel*; on conflicting rules, default tunnel |
| State unclear, configuration invalid or file permissions unsafe | fail-safe: default tunnel on |
| Captive portal (hotel, train) | tunnel waits until Windows reports internet access |
| Tunnel fails to start | one event log entry, retries after 30 s, 2 min and 10 min |

A **trusted network** (no tunnel) needs the gateway MAC **plus** a DNS suffix, SSID or BSSID. A Wi-Fi name alone can be spoofed by anyone.

## Command line

| Command | Purpose |
|---|---|
| `wgas install` / `uninstall [/purge]` | install or remove the service (admin); `/purge` also deletes tunnels and configuration |
| `wgas import <a.conf> [...]` / `remove <tunnel>` | manage tunnels (admin); the file name becomes the tunnel name |
| `wgas status` | state, networks and target tunnel |
| `wgas check` / `reload` | validate or apply `config.ini` (admin) |
| `wgas connect <tunnel>` / `disconnect` / `auto` | switch manually, or hand control back to the automation |
| `wgas pause <min>` / `resume` | pause or resume the automation |
| `wgas version` | show the version |

Configuration file: `%ProgramData%\WgAutoSwitch\config.ini` (normally edited through the GUI; see `config.example.ini`).
Event log: *Windows Logs › Application*, source `WgAutoSwitch`. Only state changes and errors are logged.

## Code signing

See [CODE_SIGNING.md](CODE_SIGNING.md). Windows release binaries will be signed via the SignPath Foundation once the project is accepted: *Free code signing provided by [SignPath.io](https://signpath.io), certificate by [SignPath Foundation](https://signpath.org).* Until then, Windows SmartScreen warns on first start (*More info › Run anyway*).

## Security

- The service runs as the virtual account `NT SERVICE\WgAutoSwitch` with only `SeChangeNotifyPrivilege` and `SeCreateGlobalPrivilege` (for the state signal to the GUI). On the WireGuard tunnel services it may only start, stop and query status, granted by service ACL.
- Named pipe `\\.\pipe\WgAutoSwitch`: local only, network logons denied; accessible to SYSTEM, Administrators and interactively signed-in users. It accepts only status, connect, disconnect and pause. Configuration and keys can only be changed by Administrators.
- The GUI checks that the pipe server really is the service (process ID) and connects at identification level only.
- No listening ports, no telemetry. The only network access is the update check described in [PRIVACY.md](PRIVACY.md); updates are installed only after confirmation and only if correctly signed.
- `config.ini` is owned by Administrators; the service can only read it. If the file permissions are unsafe, the fail-safe applies.
- Kill switch: use `AllowedIPs = 0.0.0.0/0, ::/0` in the `.conf`. WireGuard for Windows then blocks untunneled traffic while the tunnel is up.

## Energy

The service sleeps in a single wait call without a timeout. It is only woken by Windows notifications (interface, address and connectivity changes, resume from standby), by requests from the GUI, or by one-shot timers armed after such an event. While idle there is no polling and there are no timers. The process runs with EcoQoS and background priority. With the window hidden, the GUI waits only for the service's state signal; the 2-second refresh of the traffic counters runs only while the window is visible.

## Known limitations

- **SSID/BSSID on Windows 11 24H2+** may only be readable with location services enabled. If missing, the Wi-Fi network is treated as unknown (fail-safe); rules based on gateway MAC plus DNS suffix keep working.
- **Handshake time** is not shown: the official WireGuard installation exposes it to Administrators only. The GUI shows the adapter's traffic counters instead.
- Requires the official WireGuard for Windows installation (driver and tunnel services).

## Build from source

Requirements: [Build Tools for Visual Studio 2026](https://visualstudio.microsoft.com/downloads/) (Visual Studio 2022 works as well) with
- workload *Desktop development with C++*
- *MSVC ARM64 build tools* (for ARM64) and *MSVC x64/x86 build tools* (for x64)
- Windows 11 SDK (10.0.22621 or newer)

No other dependencies: C++20 and Win32 only, no frameworks. `build.cmd` finds the newest installed Visual Studio / Build Tools via `vswhere` and works from a plain command prompt. Building from the Visual Studio IDE also works: open the folder and use the tasks from `tasks.vs.json` (right-click the root folder).

```bat
build.cmd test      & rem unit tests (decision logic, translation table)
build.cmd           & rem -> build\arm64\wgas.exe and build\arm64\wgas-gui.exe
build.cmd x64       & rem x64 build
```

Each binary is about 140–160 KB. If `wgas-gui.exe` is still running, the linker cannot overwrite it, so choose **Exit** in the tray menu first. Optionally `set WGAS_SIGN_THUMB=<certificate thumbprint>` signs both binaries.

### Continuous integration and releases

[`.github/workflows/build.yml`](.github/workflows/build.yml) runs the tests and builds ARM64 and x64 on every push. Pushing a version tag creates a draft release with both ZIP packages and `SHA256SUMS.txt`:

```bat
git tag v1.3.1
git push origin v1.3.1
```

To release, raise the version in [`src/version.h`](src/version.h) (the only place it is defined), commit, then push the tag `v<version>`. The workflow refuses tags that do not match `version.h`.

Each release ZIP contains `wgas.exe`, `wgas-gui.exe`, `INSTALLATION.txt` (English/German), `README.md`, `config.example.ini` and the license. Release binaries are signed via SignPath once the project is accepted; see [CODE_SIGNING.md](CODE_SIGNING.md).

## Layout

```
src/decide.h     decision logic (no Windows headers; unit tests in tests/)
src/i18n.*       language selection; src/i18n_table.h holds the German/English texts
src/common.*     paths, config read/write, network features, tunnel services, pipe client
src/wgas.cpp     service (event loop, pipe server) and command line
src/gui.cpp      tray, main window, rule editor, tunnel editor (elevated mode)
src/update.*     update check and download (WinHTTP, SHA-256, signature pre-check)
src/version.h    version number and repository (single source for code, resources and CI)
build.cmd        reproducible build (MSVC, ARM64/x64)
```
