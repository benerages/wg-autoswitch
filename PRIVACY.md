# Privacy policy

WG-AutoSwitch has no telemetry and sends no usage or network data anywhere.

## What stays on your computer

To choose the right tunnel, the service reads local network features (network type, gateway MAC address, DNS suffix, Wi-Fi name and access point). They are evaluated locally, written to the Windows event log only when the tunnel state changes, and never transmitted.

## Update check (the only network access of WG-AutoSwitch itself)

- **What:** the tray app (`wgas-gui.exe`) asks GitHub for the latest release of this project: `https://api.github.com/repos/benerages/wg-autoswitch/releases/latest`.
- **When:** about one minute after the tray app starts, then at most once every 20 hours, and whenever you choose **Check for updates**.
- **What is transmitted:** only what any HTTPS request contains – your IP address and the user agent `WG-AutoSwitch/<version>`. No identifiers, no network names, no configuration.
- **Who receives it:** GitHub, Inc. ([GitHub Privacy Statement](https://docs.github.com/site-policy/privacy-policies/github-general-privacy-statement)).
- **Downloads:** an update is only downloaded after you confirm it. The package comes from this project's GitHub releases; its SHA-256 checksum and Authenticode signature (publisher *SignPath Foundation*) are verified before installation.
- **Turn it off:** tray menu › **Check for updates automatically** (uncheck). Manual checks still work.

## WireGuard

The VPN connections themselves are made by the official [WireGuard for Windows](https://www.wireguard.com/) to the servers in your tunnel configuration. WG-AutoSwitch only starts and stops these tunnels.
