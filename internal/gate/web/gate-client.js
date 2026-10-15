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
      var wait = Math.max(30000, life * 2 / 3);
      renewAt = Date.now() + wait;
      clearTimeout(timer);
      timer = setTimeout(renew, wait);
    }
    function renew() {
      signIn().then(function (s) { schedule(s.expires_at); }, function (err) {
        if (err.status === 401 || err.status === 0) {
          location.assign("/_lanternfish/?next=" + encodeURIComponent(location.pathname + location.search + location.hash));
        } else {
          clearTimeout(timer);
          timer = setTimeout(renew, 30000);
        }
      });
    }
    // Timers are throttled in background tabs; catch up when the tab returns.
    document.addEventListener("visibilitychange", function () {
      if (document.visibilityState === "visible" && Date.now() >= renewAt) renew();
    });
    renew();
  }

  window.LanternfishGate = { enroll: enroll, signIn: signIn, hasDevice: hasDevice, forget: forget };

  var me = document.currentScript;
  if (me && me.hasAttribute("data-autorenew")) autoRenew();
})();
