// Approve a TV's pending verification from a phone: /_lanternfish/pair
(function () {
  "use strict";

  var W = window.LanternfishWebAuthn;
  var status = document.getElementById("status");
  var base = "";
  function $(id) { return document.getElementById(id); }
  function fail(err) { status.textContent = (err && err.message) || "Something went wrong."; }

  function fact(name, value) {
    if (!value) return;
    var dt = document.createElement("dt"), dd = document.createElement("dd");
    dt.textContent = name;
    dd.textContent = value;
    $("facts").appendChild(dt);
    $("facts").appendChild(dd);
  }

  function render(v) {
    var left = v.required_all.filter(function (f) { return v.done.indexOf(f) < 0; });
    $("totp").hidden = left.indexOf("totp") < 0;
    $("passkey").hidden = left.indexOf("webauthn") < 0;
    status.textContent = left.length
      ? "Still needed: " + left.map(function (f) { return f === "totp" ? "authenticator code" : "passkey"; }).join(" and ") + "."
      : "Approved. The device continues by itself; you can close this page.";
  }

  $("lookup").addEventListener("submit", function (e) {
    e.preventDefault();
    W.call("/_lanternfish/v2/pair", { code: $("pcode").value }).then(function (v) {
      base = "/_lanternfish/v2/verification/" + encodeURIComponent(v.verification_id);
      $("lookup").hidden = true;
      $("review").hidden = false;
      fact("Device", v.device_name + (v.platform ? " (" + v.platform + ")" : ""));
      fact("Why", { network_changed: "new network", new_device: "adding a new device", new_country: "new country",
        location_unknown: "unknown location", mac_changed: "network address changed" }[v.reason] || v.reason);
      fact("Network", v.network);
      fact("Country", v.country);
      fact("Device key", v.key_fingerprint);
      render(v);
    }, function (err) {
      status.textContent = err.status === 404 ? "That code is wrong or has expired (codes work once)." : err.message;
    });
  });

  $("totp").addEventListener("submit", function (e) {
    e.preventDefault();
    W.call(base + "/totp", { code: $("code").value }).then(function (v) { $("code").value = ""; render(v); }, function (err) {
      $("code").value = "";
      if (err.data && err.data.error === "code_not_accepted") status.textContent = "Code not accepted (" + err.data.attempts_left + " tries left).";
      else fail(err);
    });
  });

  $("passkey").addEventListener("click", function () {
    W.call(base + "/webauthn/options", {}).then(W.get).then(function (cred) {
      return W.call(base + "/webauthn/finish", cred);
    }).then(render, function (err) {
      if (err && err.name === "NotAllowedError") { status.textContent = "The passkey prompt was cancelled."; return; }
      fail(err);
    });
  });
})();
