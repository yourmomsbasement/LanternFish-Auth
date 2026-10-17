// The additional-verification page: /_lanternfish/verify#id=…[&enroll=1][&next=…]
(function () {
  "use strict";

  var W = window.LanternfishWebAuthn, G = window.LanternfishGate;
  var status = document.getElementById("status");
  var detail = document.getElementById("detail");
  var params = new URLSearchParams(location.hash.slice(1));
  var id = params.get("id") || "";
  var enrolling = params.get("enroll") === "1";
  var next = params.get("next") || "/";
  // Keep the handle out of the address bar (and so out of history).
  history.replaceState(null, "", location.pathname);
  var base = "/_lanternfish/v2/verification/" + encodeURIComponent(id);
  var finishing = false, pollTimer = null;

  function safeNext() {
    if (next.charAt(0) !== "/") return "/";
    try {
      var u = new URL(next, location.origin);
      return u.origin === location.origin ? u.pathname + u.search + u.hash : "/";
    } catch (e) { return "/"; }
  }

  var REASONS = {
    reauthentication_required: "Your policy requires you to verify again because the authentication interval has elapsed.",
    network_changed: "This device is signing in from a network it isn't approved for.",
    new_device: "A new device is being added for this owner.",
    new_country: "This device is signing in from a new country.",
    location_unknown: "This connection's location can't be determined.",
    mac_changed: "This device reported a different network address than before."
  };
  var NAMES = { totp: "authenticator code", webauthn: "passkey" };

  function show(el, on) { document.getElementById(el).hidden = !on; }

  function render(v) {
    var left = v.required_all.filter(function (f) { return v.done.indexOf(f) < 0; });
    status.textContent = left.length
      ? "Needed: " + v.required_all.map(function (f) { return NAMES[f] + (v.done.indexOf(f) >= 0 ? " ✓" : ""); }).join(" AND ")
      : "Approved. Finishing…";
    detail.textContent = (REASONS[v.reason] || "") + " Device: " + v.device_name +
      (v.network ? " · network " + v.network : "") + (v.country ? " · " + v.country : "") +
      " · " + Math.max(0, Math.round(v.expires_in_seconds / 60)) + " min left.";
    show("totp", left.indexOf("totp") >= 0);
    show("passkey", left.indexOf("webauthn") >= 0);
    show("pairing", left.length > 0);
    if (!left.length) finish();
  }

  function refresh() {
    return W.call(base).then(render, fail);
  }

  function fail(err) {
    if (err && err.status === 404) {
      status.textContent = "This approval request expired or was cancelled.";
      detail.textContent = "";
      ["totp", "passkey", "pairing", "recovery"].forEach(function (x) { show(x, false); });
      var a = document.createElement("a");
      a.href = "/_lanternfish/?next=" + encodeURIComponent(safeNext());
      a.textContent = "Start again";
      detail.appendChild(a);
      clearInterval(pollTimer);
      return;
    }
    status.textContent = (err && err.message) || "Something went wrong.";
  }

  function finish() {
    if (finishing) return;
    finishing = true;
    clearInterval(pollTimer);
    var done = enrolling
      ? G.finishEnrollment().then(function () { return G.signIn(); })
      : G.completeVerification(id);
    done.then(function () { location.replace(safeNext()); }, function (err) {
      finishing = false;
      if (err.status === 403 && err.data && err.data.error === "additional_verification_required") {
        // Another check is needed (e.g. location, after the network): continue there.
        id = err.data.verification_id;
        base = "/_lanternfish/v2/verification/" + encodeURIComponent(id);
        enrolling = false;
        return refresh();
      }
      if (err.status === 409 && err.data && err.data.error === "verification_restart") {
        status.textContent = "Something changed while you were approving (" + err.data.reason + "). Start again.";
        return;
      }
      fail(err);
    });
  }

  document.getElementById("totp").addEventListener("submit", function (e) {
    e.preventDefault();
    var code = document.getElementById("code");
    W.call(base + "/totp", { code: code.value }).then(function (v) { code.value = ""; render(v); }, function (err) {
      code.value = "";
      if (err.data && err.data.error === "code_not_accepted") {
        status.textContent = "That code wasn't accepted (" + err.data.attempts_left + " tries left). Check the phone's clock is automatic.";
        if (!err.data.attempts_left) refresh();
      } else fail(err);
    });
  });

  document.getElementById("lost").addEventListener("click", function () { show("recovery", true); });
  document.getElementById("recovery").addEventListener("submit", function (e) {
    e.preventDefault();
    W.call(base + "/recovery", { code: document.getElementById("rcode").value }).then(function (r) {
      // Set up a new authenticator, then come back here.
      var back = "/_lanternfish/verify#id=" + encodeURIComponent(id) + (enrolling ? "&enroll=1" : "") +
        "&next=" + encodeURIComponent(safeNext());
      location.assign("/_lanternfish/setup#grant=" + encodeURIComponent(r.setup_grant) + "&back=" + encodeURIComponent(back));
    }, fail);
  });

  document.getElementById("passkeyButton").addEventListener("click", function () {
    if (!W.supported()) { status.textContent = "This browser can't use passkeys here. Approve on your phone instead."; return; }
    W.call(base + "/webauthn/options", {}).then(W.get).then(function (cred) {
      return W.call(base + "/webauthn/finish", cred);
    }).then(render, function (err) {
      if (err && err.name === "NotAllowedError") { status.textContent = "The passkey prompt was cancelled."; return; }
      fail(err);
    });
  });

  document.getElementById("pairButton").addEventListener("click", function () {
    W.call(base + "/pairing", {}).then(function (p) {
      var info = document.getElementById("pairInfo");
      info.hidden = false;
      info.textContent = "On your phone, open " + location.origin + p.pair_url + " and enter " + p.pairing_code +
        ". This page continues by itself once you've approved there.";
      clearInterval(pollTimer);
      pollTimer = setInterval(refresh, 3000);
    }, fail);
  });

  if (!id) { status.textContent = "Nothing to approve here."; return; }
  refresh();
})();
