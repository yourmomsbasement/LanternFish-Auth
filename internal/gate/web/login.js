(function () {
  "use strict";

  var status = document.getElementById("status");
  var form = document.getElementById("enroll");
  var button = form.querySelector("button");

  function nextPath() {
    var n = new URLSearchParams(location.search).get("next") || "/";
    // SECURITY: only same-origin paths. Checking the string alone isn't
    // enough: URL parsing drops tabs and newlines, so "/\t/evil.example"
    // becomes "//evil.example". Resolve it the way the browser will.
    if (n.charAt(0) !== "/") return "/";
    try {
      var u = new URL(n, location.origin);
      if (u.origin !== location.origin) return "/";
      return u.pathname + u.search + u.hash;
    } catch (e) {
      return "/";
    }
  }

  var REASONS = {
    outside_schedule: "Access isn't allowed at this time.",
    owner_disabled: "Access for this device's owner is turned off.",
    network_changed: "This device isn't allowed to sign in from this network.",
    network_not_approved: "This device isn't allowed to sign in from this network.",
    credential_mismatch: "This connection presented two different devices' credentials.",
    device_revoked: "This device has been revoked.",
    could_not_save_network_approval: "The Gate couldn't record this network. Try again in a minute."
  };
  function reasonText(code) { return REASONS[code] || ""; }

  function showEnroll(message) {
    status.textContent = message;
    form.hidden = false;
    document.getElementById("ticket").focus();
  }

  function signIn() {
    status.textContent = "Signing in…";
    return window.LanternfishGate.signIn().then(function () { location.replace(nextPath()); });
  }

  if (!window.isSecureContext || !window.crypto || !crypto.subtle || !window.indexedDB) {
    status.textContent = "This browser can't hold a device key here. It needs HTTPS, WebCrypto and IndexedDB, " +
      "and private windows may not keep keys.";
    return;
  }

  window.LanternfishGate.hasDevice().then(function (has) {
    if (!has) {
      showEnroll("This browser isn't enrolled yet. Paste an enrollment ticket from Lanternfish Builder.");
      return;
    }
    var why = reasonText(new URLSearchParams(location.search).get("reason") || "");
    if (why) status.textContent = why + " Checking again…";
    return signIn().catch(function (err) {
      if (err.status === 403 || err.status === 503) {
        status.textContent = (reasonText(err.reason) || "Access denied.") + " (" + (err.reason || err.message) + ")";
      } else if (err.status === 401) {
        showEnroll("This browser's key was not accepted. It may have been revoked. Enroll again with a new ticket.");
      } else {
        status.textContent = "Sign-in failed: " + err.message;
      }
    });
  }, function (err) {
    status.textContent = "Could not open key storage: " + err.message;
  });

  form.addEventListener("submit", function (e) {
    e.preventDefault();
    var ticket = document.getElementById("ticket").value.trim();
    var name = document.getElementById("name").value.trim();
    if (!ticket) return;
    button.disabled = true;
    status.textContent = "Creating this browser's key and enrolling…";
    window.LanternfishGate.enroll(ticket, name).then(signIn).catch(function (err) {
      status.textContent = "Enrollment failed: " + err.message;
      button.disabled = false;
    });
  });
})();
