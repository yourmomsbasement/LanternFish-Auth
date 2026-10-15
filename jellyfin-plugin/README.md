# Lanternfish Gate plugin for Jellyfin

This plugin makes Jellyfin refuse every request that Lanternfish Gate didn't
forward and sign. If Jellyfin's port is exposed by mistake, through a
forgotten Docker `ports:` line, a firewall change or a router's UPnP, direct
requests still get `403 Forbidden`.

It is a second lock. Keep Jellyfin off the network as well; see
`deploy/docker-compose.yml`.

## How it works

The Gate signs each forwarded request with its own ECDSA P-256 key. It signs
the method, the exact request target, a timestamp, a single-use nonce and the
device ID. The plugin runs ahead of all of Jellyfin's own middleware. It
checks the signature against the Gate's **public** key, rejects timestamps
more than 30 seconds off, and rejects any nonce it has already seen. Jellyfin
never holds anything that could be used to forge Gate traffic. The full
format is in [docs/PROTOCOL.md](../docs/PROTOCOL.md#signed-requests-to-jellyfin).

## Build

Requires the .NET 10 SDK. Built against Jellyfin 12.2 (`targetAbi` 12.2.0.0).

```sh
dotnet publish Jellyfin.Plugin.LanternfishGate -c Release -o out
```

## Install

1. Copy `out/Jellyfin.Plugin.LanternfishGate.dll` and `out/meta.json` into
   Jellyfin's plugins directory, in a folder named
   `LanternfishGate_1.0.0.0`:
   * Docker: `/config/plugins/LanternfishGate_1.0.0.0/`
   * Linux packages: `/var/lib/jellyfin/plugins/LanternfishGate_1.0.0.0/`
   * Windows: `%ProgramData%\Jellyfin\Server\plugins\LanternfishGate_1.0.0.0\`
2. Restart Jellyfin. Until a key is configured the plugin **does not
   enforce**; it only logs a warning. That way, installing it can't lock you
   out.
3. Run `lanternfish-gate upstream-key` (the key is also printed in the Gate's
   log at startup). Through the Gate, open **Dashboard → Plugins → Lanternfish
   Gate**, paste the key and save. Enforcement starts immediately.

You can also write the settings file before the first start:
`plugins/configurations/Jellyfin.Plugin.LanternfishGate.xml`

```xml
<?xml version="1.0" encoding="utf-8"?>
<PluginConfiguration>
  <GatePublicKeys>MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE…</GatePublicKeys>
  <MaxClockSkewSeconds>30</MaxClockSkewSeconds>
  <AllowLoopbackHealthCheck>true</AllowLoopbackHealthCheck>
</PluginConfiguration>
```

## Settings

| Setting | Default | Meaning |
|---|---|---|
| Gate public keys | empty | One base64 key per line. Empty means not enforcing. When rotating, add the new key before removing the old one. |
| Allowed clock difference | 30 s | Keep the Gate and Jellyfin on NTP. |
| Allow unsigned health checks from this machine | on | Lets `GET /health` from loopback through, for the Docker health check. |

An unparseable key makes the plugin **refuse every request** (`503`) rather
than quietly letting traffic through. If that locks you out, fix the XML file
above, or remove the plugin folder, and restart Jellyfin.

## Locked out?

Either delete `plugins/LanternfishGate_1.0.0.0/`, or clear `GatePublicKeys` in
the XML file, then restart Jellyfin.
