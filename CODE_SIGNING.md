# Code signing policy

**Status:** application to the [SignPath Foundation](https://signpath.org) open-source program pending. Until it is approved, release binaries are unsigned.

Once approved, Windows release binaries (`wgas.exe`, `wgas-gui.exe`, ARM64 and x64) will be signed with:

> Free code signing provided by [SignPath.io](https://signpath.io), certificate by [SignPath Foundation](https://signpath.org).

## How releases are built

- Every release is built from this repository by the GitHub Actions workflow [`.github/workflows/build.yml`](.github/workflows/build.yml) on GitHub-hosted runners. No locally built binaries are signed.
- A signing request is only submitted for version tags (`v*`) and must be approved in SignPath before anything is signed.
- Only this project's own binaries are signed. WireGuard for Windows is not bundled and is not signed by this project.

## Team roles

| Role | Members |
|---|---|
| Committers and reviewers | [benerages](https://github.com/benerages) |
| Approvers | [benerages](https://github.com/benerages) |

All members use multi-factor authentication for GitHub and SignPath.

## Privacy

This program will not transfer any information to other networked systems unless specifically requested by the user or the person installing or operating it, with one disclosed exception: a daily check for new releases on GitHub, which can be turned off in the tray menu. See [PRIVACY.md](PRIVACY.md).
