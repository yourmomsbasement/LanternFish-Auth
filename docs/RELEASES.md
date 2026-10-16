# Signed releases and updates

Gates install only releases whose manifest is signed by a key you trust. The
Gate itself only verifies; signing happens on your admin PC with
[`scripts/sign-releases.sh`](../scripts/sign-releases.sh), and the key never
leaves that machine.

```
GitHub Actions                 admin PC                             Gate (CT 200)
──────────────                 ────────                             ─────────────
builds the archives            sign-releases.sh sign                dashboard → Updates → Install
+ lanternfish-release.json ──► downloads every file, checks its ──► updater (root) verifies the
  (SHA-256 of every file)      SHA-256, signs, uploads the .sig     signature again, installs,
                                                                    health-checks, rolls back
```

The signature is Ed25519 over the line `lanternfish-release/v1`, a newline,
and the manifest file's exact bytes, stored as
`{"key_id": "<first 16 hex digits of SHA-256(public key)>", "signature": "<base64>"}`
in `lanternfish-release.json.sig`.

## One-time setup

### 1. On your admin PC

Needs `bash`, `openssl` 1.1.1 or newer, `curl`, `jq` and `sha256sum`
(Debian/Ubuntu: `apt install openssl curl jq`). Copy
`scripts/sign-releases.sh` from the repository somewhere on your `PATH`.

**Create your signing key:**

```sh
sign-releases.sh keygen
```

It asks for a passphrase (12+ characters), writes the key to
`~/.config/lanternfish/release-key.pem` (Ed25519, encrypted PKCS#8 with an
scrypt-derived key), and prints its public key line:

```
lfrk1 jC3F7rgUiYR6ChC9Oy2mN84L1d3HqrZXi1ZRCx85Afw= you@admin-vm 2026-10-16
```

* Back the key file up offline (a USB stick, your password manager). Never
  upload it, and never store the passphrase on the machine.
* If you lose it, make a new one and replace the public key on your Gates.
  If it leaks, do that at once.

**Let the script upload signatures:** create a fine-grained GitHub token at
GitHub → Settings → Developer settings → Fine-grained tokens, with access to
only this repository and the permission **Contents: Read and write** (that's
what attaching a file to a release needs). Give it an expiry date. Then:

```sh
install -m 600 /dev/null ~/.config/lanternfish/github-token
nano ~/.config/lanternfish/github-token     # paste the token
```

Without a token the script still signs; you then attach
`signed/<tag>/lanternfish-release.json.sig` to the release by hand.

The token can push to the repository, so protect `main` with a branch rule
that requires pull requests, and keep the admin PC locked down.

**Optional reminder:** a timer that pings your Discord when a release is
waiting. Put `LANTERNFISH_ALERT_WEBHOOK=https://discord.com/api/webhooks/...`
in `~/.config/lanternfish/sign.env`, then add this crontab line
(`crontab -e`):

```
0 * * * * /usr/local/bin/sign-releases.sh notify
```

### 2. On each Gate (CT 200)

Trust your key, as root:

```sh
echo 'lfrk1 jC3F…Afw= you@admin-vm 2026-10-16' >> /etc/lanternfish/release-keys
systemctl restart lanternfish-gate
```

The file holds only public keys. You can list two (your key and a spare kept
offline) to rotate without a gap.

`install-gate.sh` from any release since 0.2.0 installs the updater:

* `lanternfish-gate-update.path` watches for requests from the dashboard and
  starts `lanternfish-gate-update.service` (root) to install them.
* `lanternfish-gate-update-auto.timer` runs nightly. It installs nothing
  unless you set `LANTERNFISH_AUTO_UPDATE` in `/etc/lanternfish/gate.env`:
  `patch` (x.y.**Z** only), `minor` (x.**Y**.z), or `all`. Pre-releases are
  never installed automatically.

## Publishing a release

1. Publish a release with a new tag on GitHub, as before. The workflow builds
   everything and attaches `lanternfish-release.json`.
2. When the workflow is green, on your admin PC:

   ```sh
   sign-releases.sh pending     # what is waiting
   sign-releases.sh sign        # all waiting releases (or: sign v0.3.0)
   ```

   It downloads the manifest and **every file it lists**, checks each
   SHA-256 and size, and only then asks for your passphrase, once. If any
   file doesn't match, it signs nothing. Each signature is checked before it
   is uploaded.
3. Gates see the release as soon as the signature is attached:
   Dashboard → Updates shows it as verified and signed by your key.

## Updating a Gate

* **Dashboard:** Updates tab → Install. The Gate restarts (about 30 seconds;
  playing streams drop and browsers renew their sessions), and you sign in to
  the dashboard again.
* **Command line** (root on CT 200): `lanternfish-gate update check`, then
  `lanternfish-gate update apply` (or `-version 0.3.0`).

What the updater does:

1. Re-verifies the manifest signature itself (it doesn't trust the Gate's
   check), and that the signed manifest is for the requested version, so an
   older signed release can't be passed off as a newer one.
2. Refuses anything not newer than what runs (`-allow-downgrade` on the
   command line overrides).
3. Downloads the archive for this platform, checks its SHA-256 and size, and
   checks the new binary runs and reports the right version.
4. Stops the Gate, backs up the data file to
   `/var/lib/lanternfish-update/backups/` (the last five are kept), keeps the
   old binary as `/usr/local/lib/lanternfish/lanternfish-gate.prev`, and
   swaps in the new one.
5. Starts the Gate and checks it is running and answering TLS, and still is
   15 seconds later. If not, it restores the old binary and the data file and
   starts that again.
6. Writes the result to `/var/lib/lanternfish-update/status.json` (shown in
   the dashboard) and sends it to `LANTERNFISH_ALERT_WEBHOOK`.

The Gate itself only ever writes a request naming a version
(`/var/lib/lanternfish/update-request.json`). It can't install anything,
and the dashboard can only request the newest verified release.

### By hand

```sh
journalctl -u lanternfish-gate-update -n 50      # what the updater did
cat /var/lib/lanternfish-update/status.json
# Undo the last update yourself:
systemctl stop lanternfish-gate
cp /usr/local/lib/lanternfish/lanternfish-gate.prev /usr/local/bin/lanternfish-gate
cp /var/lib/lanternfish-update/backups/gate.json.<version>.<time> /var/lib/lanternfish/gate.json
chown lanternfish:lanternfish /var/lib/lanternfish/gate.json
systemctl start lanternfish-gate
```

## Windows

Gates on Windows don't update themselves. Check a release by hand with
`lanternfish-gate release-verify -keys release-keys lanternfish-release.json lanternfish-release.json.sig`
(and the archive against the manifest), then replace the binary. The signing
script runs on Linux or macOS (or WSL).
