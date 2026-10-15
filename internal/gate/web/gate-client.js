// Lanternfish Gate browser client.
//
// The device key is a non-extractable WebCrypto ECDSA P-256 key kept in
// IndexedDB: the page can ask the browser to sign with it, but cannot read it.
//
// Include with data-autorenew to keep the session alive in a long-running app
// (for example the Jellyfin web client):
//   <script src="/_lanternfish/gate-client.js" data-autorenew></script>
(function () {
  "use strict";

  var DB_NAME = "lanternfish-gate";
  var STORE = "keys";
  var RECORD = "device";
  var API = "/_lanternfish/v1/";
  var ENROLL_CONTEXT = "lanternfish-gate/v1/enroll\n";
  var SESSION_CONTEXT = "lanternfish-gate/v1/session\n";

  function openDB() {
    return new Promise(function (resolve, reject) {
      var req = indexedDB.open(DB_NAME, 1);
      req.onupgradeneeded = function () { req.result.createObjectStore(STORE); };
      req.onsuccess = function () { resolve(req.result); };
      req.onerror = function () { reject(req.error); };
    });
  }

  function withStore(mode, fn) {
    return openDB().then(function (db) {
      return new Promise(function (resolve, reject) {
        var tx = db.transaction(STORE, mode);
        var req = fn(tx.objectStore(STORE));
        tx.oncomplete = function () { db.close(); resolve(req.result); };
        tx.onerror = tx.onabort = function () { db.close(); reject(tx.error); };
      });
    });
  }

  function loadDevice() { return withStore("readonly", function (s) { return s.get(RECORD); }); }
  function saveDevice(rec) { return withStore("readwrite", function (s) { return s.put(rec, RECORD); }); }
  function forget() { return withStore("readwrite", function (s) { return s.delete(RECORD); }); }

  function b64(buf) {
    var bytes = new Uint8Array(buf), s = "";
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
  }

  function sign(key, message) {
    return crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, new TextEncoder().encode(message));
  }

  function post(path, body) {
    return fetch(API + path, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    }).then(function (res) {
      return res.json().catch(function () { return {}; }).then(function (data) {
        if (!res.ok) {
          var err = new Error(data.error || "HTTP " + res.status);
          err.status = res.status;
          err.reason = data.reason || "";
          throw err;
        }
        return data;
      });
    });
  }

  function enroll(ticket, name) {
    var pair;
    return crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"])
      .then(function (p) {
        pair = p;
        return Promise.all([
          crypto.subtle.exportKey("spki", pair.publicKey),
          sign(pair.privateKey, ENROLL_CONTEXT + ticket)
        ]);
      })
      .then(function (r) {
        var body = { ticket: ticket, public_key: b64(r[0]), proof: b64(r[1]) };
        if (name) body.name = name;
        return post("enroll", body);
      })
      .then(function (res) {
        return saveDevice({ deviceId: res.device_id, privateKey: pair.privateKey }).then(function () { return res; });
      });
  }

  function signIn() {
    var device;
    return loadDevice()
      .then(function (d) {
        if (!d) {
          var err = new Error("This browser is not enrolled");
          err.status = 0;
          throw err;
        }
        device = d;
        return post("challenge", { device_id: d.deviceId });
      })
      .then(function (c) {
        return sign(device.privateKey, SESSION_CONTEXT + device.deviceId + "\n" + c.challenge).then(function (sig) {
          return post("session", { device_id: device.deviceId, challenge: c.challenge, signature: b64(sig) });
        });
      });
  }

  function hasDevice() { return loadDevice().then(function (d) { return !!d; }); }

  function autoRenew() {
    var timer = null;
    var renewAt = 0;
    function schedule(expiresAt) {
      var life = Date.parse(expiresAt) - Date.now();
      // Renew at about 2/3 of the session's life, jittered so tabs and
      // devices don't all renew in the same second.
      var wait = Math.max(30000, life * (0.6 + Math.random() * 0.07));
      renewAt = Date.now() + wait;
      clearTimeout(timer);
      timer = setTimeout(renew, wait);
    }
    var inflight = false;
    function renew() {
      // One renewal at a time: the timer and a tab becoming visible can
      // both fire, and each sign-in creates a new session on the Gate.
      if (inflight) return;
      inflight = true;
      signIn().then(function (s) { inflight = false; schedule(s.expires_at); }, function (err) {
        inflight = false;
        if (err.status === 401 || err.status === 0) {
          location.assign("/_lanternfish/?next=" + encodeURIComponent(location.pathname + location.search + location.hash));
        } else if (err.status === 403) {
          // The policy says no (outside the schedule, network not allowed,
          // owner disabled). Retrying won't change that, and navigating away
          // would stop playback that is allowed to finish; the next page
          // request goes to the sign-in page, which shows why.
          clearTimeout(timer);
        } else {
          clearTimeout(timer);
          timer = setTimeout(renew, 20000 + Math.random() * 20000);
        }
      });
    }
    // Timers are throttled in background tabs; catch up when the tab returns.
    document.addEventListener("visibilitychange", function () {
      if (document.visibilityState === "visible" && Date.now() >= renewAt) renew();
    });
    // A new network (Wi-Fi to mobile data) invalidates network-bound
    // sessions; sign in again from it straight away.
    window.addEventListener("online", function () { renew(); });
    renew();
  }

  window.LanternfishGate = { enroll: enroll, signIn: signIn, hasDevice: hasDevice, forget: forget };

  var me = document.currentScript;
  if (me && me.hasAttribute("data-autorenew")) autoRenew();
})();
