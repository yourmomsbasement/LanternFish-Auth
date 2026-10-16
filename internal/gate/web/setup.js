// Owner factor setup: /_lanternfish/setup#grant=…[&back=…]
(function () {
  "use strict";

  var W = window.LanternfishWebAuthn;
  var status = document.getElementById("status");
  var params = new URLSearchParams(location.hash.slice(1));
  var grant = params.get("grant") || "";
  var back = params.get("back") || "";
  history.replaceState(null, "", location.pathname);
  var API = "/_lanternfish/v2/factors/";

  function $(id) { return document.getElementById(id); }
  function fail(err) { status.textContent = (err && err.message) || "Something went wrong."; }
  function safeBack() {
    if (back.indexOf("/_lanternfish/verify#") !== 0) return "";
    return back;
  }

  function load() {
    return W.call(API + "setup/info", { grant: grant }).then(function (i) {
      status.textContent = "For " + i.owner + ". This link works for " + Math.round(i.expires_in_seconds / 60) + " more minutes.";
      $("totpSection").hidden = false;
      $("totpState").textContent = i.has_totp
        ? (i.recovery ? "Your old authenticator will be replaced." : "An authenticator app is set up (" + i.recovery_codes_left + " recovery codes left).")
        : "Not set up yet.";
      $("totpStart").hidden = i.has_totp && !i.recovery;
      $("newCodes").hidden = !i.has_totp;
      $("passkeySection").hidden = !i.webauthn_available;
      $("passkeyState").textContent = i.passkeys ? i.passkeys + " registered." : "None registered yet.";
      if (safeBack()) $("done").textContent = "Continue signing in";
    }, function (err) {
      status.textContent = err.status === 404 ? "This setup link has expired or was already used. Ask the administrator for a new one." : err.message;
    });
  }

  $("totpStart").addEventListener("click", function () {
    W.call(API + "totp/setup", { grant: grant }).then(function (s) {
      $("totpSetup").hidden = false;
      $("totpStart").hidden = true;
      $("otpLink").href = s.otpauth_uri;
      $("secret").textContent = s.secret.replace(/(.{4})/g, "$1 ").trim();
      var qr = $("qr");
      while (qr.firstChild) qr.removeChild(qr.firstChild);
      if (s.qr && s.qr.rows.length) qr.appendChild(W.qrSVG(s.qr.rows, "QR code for your authenticator app"));
      $("code").focus();
    }, fail);
  });

  function showCodes(codes) {
    $("codes").hidden = false;
    $("codeList").textContent = codes.join("\n");
  }

  $("totpConfirm").addEventListener("submit", function (e) {
    e.preventDefault();
    W.call(API + "totp/confirm", { grant: grant, code: $("code").value }).then(function (r) {
      $("totpSetup").hidden = true;
      status.textContent = "Authenticator app set up.";
      showCodes(r.recovery_codes);
      load();
    }, function (err) {
      $("code").value = "";
      fail(err);
    });
  });

  $("newCodes").addEventListener("click", function () {
    if (!confirm("Make new recovery codes? The old ones stop working.")) return;
    W.call(API + "recovery-codes", { grant: grant }).then(function (r) { showCodes(r.recovery_codes); }, fail);
  });

  $("passkeyForm").addEventListener("submit", function (e) {
    e.preventDefault();
    if (!W.supported()) { status.textContent = "This browser can't create passkeys here."; return; }
    W.call(API + "passkey/options", { grant: grant, name: $("pkname").value }).then(W.create).then(function (cred) {
      return W.call(API + "passkey/finish", cred, { "X-Lanternfish-Grant": grant });
    }).then(function (r) {
      status.textContent = "Passkey \"" + r.name + "\" added (attestation: " + r.attestation.replace("_", " ") + ").";
      $("pkname").value = "";
      load();
    }, function (err) {
      if (err && err.name === "NotAllowedError") { status.textContent = "The passkey prompt was cancelled."; return; }
      if (err && err.name === "InvalidStateError") { status.textContent = "That authenticator is already registered."; return; }
      fail(err);
    });
  });

  $("done").addEventListener("click", function () {
    var b = safeBack();
    var end = b ? Promise.resolve() : W.call(API + "done", { grant: grant });
    end.then(function () {
      if (b) { location.assign(b); return; }
      status.textContent = "All set. You can close this page.";
      ["totpSection", "passkeySection", "done"].forEach(function (x) { $(x).hidden = true; });
    }, fail);
  });

  if (!grant) { status.textContent = "Open the setup link the administrator gave you."; return; }
  load();
})();
