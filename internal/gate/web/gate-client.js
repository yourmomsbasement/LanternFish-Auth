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
  var PENDING = "pending-enrollment"; // a key waiting for the owner's approval
  var API = "/_lanternfish/v2/";
  var ENROLL_CONTEXT = "lanternfish-gate/v1/enroll\n";
  var SESSION_CONTEXT = "lanternfish-gate/v1/session\n";
  var LINK_CONTEXT = "lanternfish-gate/v2/link\n";

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
  function loadPending() { return withStore("readonly", function (s) { return s.get(PENDING); }); }
  function savePending(rec) { return withStore("readwrite", function (s) { return s.put(rec, PENDING); }); }
  function dropPending() { return withStore("readwrite", function (s) { return s.delete(PENDING); }); }

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
          var err = new Error(data.detail || data.error || "HTTP " + res.status);
          err.status = res.status;
          err.reason = data.reason || "";
          err.data = data;
          throw err;
        }
        return data;
      });
    });
  }

  // enroll creates this browser's key (or reuses the one from an earlier
  // attempt with the same ticket, which is kept in IndexedDB until it
  // succeeds) and enrolls it. It resolves to {enrolled: true}, or to
  // {verification_id} when the owner must approve first: then complete the
  // verification and call finishEnrollment().
  function enroll(ticket, name) {
    var pending;
    return loadPending().then(function (p) {
      if (p && p.ticket === ticket) return p;
      return crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"])
        .then(function (pair) {
          return crypto.subtle.exportKey("spki", pair.publicKey).then(function (spki) {
            var rec = { privateKey: pair.privateKey, publicKey: b64(spki), ticket: ticket, name: name || "" };
            return savePending(rec).then(function () { return rec; });
          });
        });
    }).then(function (p) {
      pending = p;
      return sign(p.privateKey, ENROLL_CONTEXT + ticket);
    }).then(function (proof) {
      var body = { ticket: ticket, public_key: pending.publicKey, proof: b64(proof) };
      if (pending.name) body.name = pending.name;
      return post("enrollment/begin", body);
    }).then(function (res) {
      if (res.status === "verification_required") {
        pending.verificationId = res.verification_id;
        return savePending(pending).then(function () { return { verification_id: res.verification_id, required_all: res.required_all }; });
      }
      return activated(pending, res.device);
    });
  }

  function activated(pending, device) {
    return saveDevice({ deviceId: device.device_id, privateKey: pending.privateKey })
      .then(dropPending).then(function () { return { enrolled: true, device_id: device.device_id }; });
  }

  // finishEnrollment activates an enrollment the owner has approved.
  function finishEnrollment() {
    var pending;
    return loadPending().then(function (p) {
      if (!p || !p.verificationId) throw new Error("No enrollment is waiting here; start again with the ticket.");
      pending = p;
      return sign(p.privateKey, ENROLL_CONTEXT + p.ticket);
    }).then(function (proof) {
      return post("enrollment/" + encodeURIComponent(pending.verificationId) + "/finish",
        { ticket: pending.ticket, proof: b64(proof) });
    }).then(function (res) { return activated(pending, res.device); });
  }

  function proof(path, extra) {
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
          var body = { device_id: device.deviceId, challenge: c.challenge, signature: b64(sig), client: "browser" };
          return post(path, Object.assign(body, extra || {}));
        });
      });
  }

  // signIn gets a session cookie. When the policy wants more than this
  // browser's key, it rejects with err.status 403 and
  // err.data.error "additional_verification_required" (and a verification_id).
  function signIn() { return proof("session"); }

  // completeVerification finishes a verification with a fresh key proof.
  function completeVerification(id) { return proof("verification/" + encodeURIComponent(id) + "/complete"); }

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

  // site says whether this host is an application behind the Gate, and
  // where browsers sign in.
  function site() {
    return fetch(API + "site", { credentials: "same-origin" }).then(function (res) { return res.json(); });
  }

  // linkCode asks (on the sign-in host, signed in) for a code that links
  // this browser to the application at host.
  function linkCode(host) { return post("link/code", { host: host }); }

  // link redeems a code on an application's host: this origin gets its own
  // key, recorded as linked to the device that asked for the code.
  function link(code) {
    var pair;
    return crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"])
      .then(function (p) {
        pair = p;
        return Promise.all([crypto.subtle.exportKey("spki", p.publicKey), sign(p.privateKey, LINK_CONTEXT + code)]);
      }).then(function (r) {
        return post("link/redeem", { code: code, public_key: b64(r[0]), proof: b64(r[1]) });
      }).then(function (res) {
        return saveDevice({ deviceId: res.device.device_id, privateKey: pair.privateKey });
      });
  }

  window.LanternfishGate = {
    site: site, linkCode: linkCode, link: link,
    enroll: enroll, finishEnrollment: finishEnrollment, signIn: signIn,
    completeVerification: completeVerification, hasDevice: hasDevice, forget: forget,
    hasPendingEnrollment: function () { return loadPending().then(function (p) { return !!(p && p.verificationId); }); }
  };

  var me = document.currentScript;
  if (me && me.hasAttribute("data-autorenew")) autoRenew();
})();
