# Wallet installation quickstart

This document describes the platform-specific install and uninstall hooks that
ship with the wallet bundles and installers. Every package embeds the files
referenced below so auditors can verify which actions a package performs.

## Linux

* `deploy/systemd/rpp-wallet-rpc.service` – systemd unit template that runs the
  wallet RPC service in foreground mode with `/etc/rpp-wallet/wallet.toml`.
* `deploy/install/linux/postinstall.sh` – adds `/usr/local/bin` symlinks,
  reloads systemd, and prints the location of the installed config/doc payload.
* `deploy/install/linux/prerm.sh` – removes the symlinks and systemd unit link
  and reloads `systemd` on uninstall.

To install manually from the tarball:

1. Extract the tarball under `/opt/rpp-wallet/<version>`.
2. Copy the configs under `etc/rpp-wallet/` to `/etc/rpp-wallet/`.
3. Run `hooks/postinstall.sh` as root to register the binaries and service.
4. Enable the service: `systemctl enable --now rpp-wallet-rpc.service`.

To uninstall, run `hooks/prerm.sh` before removing the files and disable the
service with `systemctl disable --now rpp-wallet-rpc.service`.

## Windows

* `deploy/install/windows/install.ps1` – adds `%ProgramFiles%\RPP Wallet` to
  the PATH for the current user and creates a Start Menu shortcut for the GUI.
* `deploy/install/windows/uninstall.ps1` – removes the shortcut and PATH entry.

Extract the `.zip` payload, run `hooks/install.ps1` from an elevated PowerShell
prompt, and then launch `RPP Wallet` from the Start Menu.

## macOS

* `deploy/install/macos/postinstall.sh` – creates a `/etc/paths.d` entry so the
  CLI is available on the PATH and prints instructions for GUI bundles.
* `deploy/install/macos/uninstall.sh` – removes the PATH entry and cached
  LaunchServices registration.

The `.pkg` installer runs the post-install hook automatically. When using the
`.dmg`, drag `rpp-wallet-gui.app` into `/Applications`, run
`hooks/postinstall.sh`, and then eject the disk image.

## Snapshot verification drill

Operators can confirm that pruning snapshots preserve wallet balances and
nonces by replaying the integration regression locally. From the repository
root run:

```sh
cargo test -p rpp-chain --locked --test pruning_cross_backend -- \
  wallet_snapshot_round_trip_default_backend
```

If the RPP-STARK backend is available, mirror the check with
`--features backend-rpp-stark` to ensure both zk backends keep wallet state
stable across snapshot/restore cycles while mempool WAL entries replay.

## Offline transaction validation

Wallet operators can validate batches of signed transactions without reaching a
node by running:

```sh
rpp-node validator tx-validate --input /path/to/transactions.json --json
```

The command verifies signatures, enforces strictly increasing nonces per
sender, and rejects zero-fee payloads. A non-zero exit code signals that one or
more entries failed validation so CI pipelines and air-gapped workflows can
block broadcast attempts before reconnecting.
