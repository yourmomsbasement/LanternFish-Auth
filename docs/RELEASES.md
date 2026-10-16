# Signed releases and updates

Gates install only releases whose manifest is signed by a key you trust. The
signing key never leaves your machine: GitHub builds the release, and you
sign it after checking the files GitHub built.

```
GitHub Actions                     you (admin PC)                     Gate (CT 200)
──────────────                     ──────────────                     ─────────────
build archives                     release-sign -tag vX.Y.Z           dashboard → Updates → Install
lanternfish-release.json  ──────►  checks every file's SHA-256 ──►   updater (root) verifies the
(SHA-256 of every file)            signs with your offline key        signature again, installs,
                                   upload the .sig to the release     health-checks, rolls back
```

## One-time setup

### 1. Create your signing key (on your admin PC)

Use the Linux release of `lanternfish-gate` (it runs anywhere; it doesn't
need to be the Gate):

```sh
lanternfish-gate release-key generate -out ~/lanternfish-release.key -comment "yourname 2026"
```

It asks for a passphrase (12+ characters) and prints the public key line:

```
lfrk1 jC3F7rgUiYR6ChC9Oy2mN84L1d3HqrZXi1ZRCx85Afw= yourname 2026
```

* The private key file is encrypted with your passphrase (PBKDF2-SHA256,
  AES-256-GCM). Keep a copy offline, for example on a USB stick and in your
  password manager. **Never** upload it to GitHub or put it on the Gate.
* If you lose it, generate a new one and replace the public key on your
  Gates. If it leaks, do the same at once, and delete the old line.

### 2. Trust it on the Gate

On CT 200, as root:

```sh
echo 'lfrk1 jC3F…Afw= yourname 2026' >> /etc/lanternfish/release-keys
```

The file is root-owned and world-readable; it holds only public keys. You
can list two (your key and a spare kept offline) to rotate without a gap.

### 3. Install the updater

`install-gate.sh` from any release since 0.2.0 installs it:

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
   lanternfish-gate release-sign -key ~/lanternfish-release.key -tag v0.3.0
   ```

   It downloads the manifest and **every file it lists**, checks each
   SHA-256, asks for your passphrase, and writes
   `lanternfish-release.json.sig`. It refuses if anything doesn't match.
3. Edit the release on GitHub and drag `lanternfish-release.json.sig` into
   the assets. Gates see the release as soon as it's attached.

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

`release-key`, `release-sign` and `update check` work on Windows. Installing
updates is Linux/systemd only; on Windows, replace the binary by hand after
`lanternfish-gate release-verify`.
