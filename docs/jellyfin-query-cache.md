# Jellyfin query cache across upgrades

Jellyfin's web client can persist query state under `jellyfin-query-cache` in
IndexedDB's `keyval-store` database. A stale value can survive a hard refresh
and cause frontend type errors even when API requests succeed.

For cookie-authenticated Jellyfin web pages, the Gate now fingerprints its own
build version and Jellyfin's external script URLs. When that fingerprint changes,
it serves a standalone preparation page before any Jellyfin application scripts.
That page removes only the `jellyfin-query-cache` key, waits for the IndexedDB
transaction to commit, sets a non-authoritative build-marker cookie, then reloads
the original page with its route fragment preserved.

The cleanup does not delete databases, enrolled device keys, other IndexedDB
records, localStorage, Jellyfin login state or authentication cookies. Browsers
without the cache database proceed without creating it. Subsequent visits on the
same build keep newly populated query state. Both plugin-injected renewal pages
and the Gate's fallback injection use the same preparation path. Hashed frontend
assets remain cacheable; the cookie-authenticated Jellyfin entry page is served
with `Cache-Control: no-store`.

The build cookie is only a cache hint and grants no access. Storage failures show
a Retry action without recording a successful migration. Close other Jellyfin
tabs and allow site storage before retrying. Existing tabs running an older
frontend should be closed during upgrades so they cannot repopulate old state.

This is a Gate-side upgrade safeguard, not a modification to Jellyfin's internal
hydration implementation. It does not attempt to repair arbitrary query-cache
corruption on an unchanged build. It applies where the existing browser renewal
injection is enabled; native certificate/header clients and other proxied
applications are unaffected.

Regression coverage uses real IndexedDB in Chromium and Firefox and checks that
a non-extractable enrolled device key still signs after cache cleanup.
