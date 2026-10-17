// Runs on a standalone maintenance page, before any Jellyfin app scripts.
(function () {
  "use strict";
  var build = document.currentScript.getAttribute("data-build");
  var status = document.getElementById("status"), retry = document.getElementById("retry");
  function clearQueryCache() {
    return new Promise(function (resolve, reject) {
      var missing = false, request = indexedDB.open("keyval-store");
      // Do not create a new database when this browser has no Jellyfin cache.
      request.onupgradeneeded = function () { missing = true; request.transaction.abort(); };
      request.onerror = function () { if (missing) resolve(); else reject(request.error); };
      request.onblocked = function () { reject(new Error("Close other Jellyfin tabs and retry.")); };
      request.onsuccess = function () {
        var db = request.result, stores = Array.from(db.objectStoreNames);
        db.onversionchange = function () { db.close(); };
        if (!stores.length) { db.close(); resolve(); return; }
        var tx = db.transaction(stores, "readwrite");
        stores.forEach(function (store) { tx.objectStore(store).delete("jellyfin-query-cache"); });
        tx.oncomplete = function () { db.close(); resolve(); };
        tx.onabort = tx.onerror = function () { db.close(); reject(tx.error || new Error("Cache cleanup failed.")); };
      };
    });
  }
  function prepare() {
    retry.hidden = true;
    status.textContent = "Preparing Jellyfin after an update…";
    if (!/^[a-f0-9]{64}$/.test(build || "")) { status.textContent = "Invalid update marker. Reload this page."; return; }
    clearQueryCache().then(function () {
      // This marker is only a cache hint, never an authentication credential.
      document.cookie = "lf_jellyfin_cache_build=" + build + "; Path=/; Max-Age=31536000; Secure; SameSite=Lax";
      if (document.cookie.split("; ").indexOf("lf_jellyfin_cache_build=" + build) < 0) throw new Error("Allow site cookies, then retry.");
      location.reload(); // retain the route fragment and force a document load
    }).catch(function () {
      status.textContent = "Could not prepare Jellyfin's query cache. Close other Jellyfin tabs, allow site storage, and retry. Your device key and login data have not been cleared.";
      retry.hidden = false;
    });
  }
  retry.onclick = prepare;
  prepare();
})();
