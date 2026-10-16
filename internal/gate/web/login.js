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
    could_not_save_network_approval: "The Gate couldn't record this network. Try again in a minute.",
    country_denied: "Access from this country isn't allowed.",
    country_not_allowed: "Access from this country isn't allowed.",
    location_unknown: "This connection's location can't be determined, and the policy requires one.",
    new_country: "Access from a new country isn't allowed for this device.",
    factor_not_set_up: "The owner hasn't set up the authenticator this policy requires. Ask the administrator for a setup link.",
    mac_report_required: "This device must report its network address, which this app doesn't do.",
    mac_report_unsupported: "This device's profile needs a native app; browsers can't use it.",
    reported_mac_changed: "This device was suspended because its reported network address changed. It must be re-enrolled.",
    verification_required: "This device needs your approval again."
  };
  function reasonText(code) { return REASONS[code] || ""; }

  function showEnroll(message) {
    status.textContent = message;
    form.hidden = false;
    document.getElementById("ticket").focus();
  }

  // toVerify goes to the verification page. The handle travels in the
  // fragment, which browsers never send to a server.
  function toVerify(id, enroll) {
    location.assign("/_lanternfish/verify#id=" + encodeURIComponent(id) + (enroll ? "&enroll=1" : "") +
      "&next=" + encodeURIComponent(nextPath()));
  }

  function signIn() {
    status.textContent = "Signing in…";
    return window.LanternfishGate.signIn().then(function () { location.replace(nextPath()); }, function (err) {
      if (err.status === 403 && err.data && err.data.error === "additional_verification_required") {
        status.textContent = "This sign-in needs your approval…";
        toVerify(err.data.verification_id, false);
        return new Promise(function () {}); // navigating
      }
      throw err;
    });
  }

  form.addEventListener("submit", function (e) {
    e.preventDefault();
    var ticket = document.getElementById("ticket").value.trim();
    var name = document.getElementById("name").value.trim();
    if (!ticket) return;
    button.disabled = true;
    status.textContent = "Creating this browser's key and enrolling…";
    window.LanternfishGate.enroll(ticket, name).then(function (res) {
      if (res.verification_id) {
        status.textContent = "The owner must approve this device…";
        toVerify(res.verification_id, true);
        return;
      }
      return signIn();
    }).catch(function (err) {
      status.textContent = "Enrollment failed: " + err.message;
      button.disabled = false;
    });
  });

  if (!window.isSecureContext || !window.crypto || !crypto.subtle || !window.indexedDB) {
    status.textContent = "This browser can't hold a device key here. It needs HTTPS, WebCrypto and IndexedDB, " +
      "and private windows may not keep keys.";
    return;
  }

  // A ticket from a scanned enrollment link: https://host/_lanternfish/#ticket=lft_…
  // The fragment never reaches a server; drop it from the address bar too.
  var linked = /(?:^#|&)ticket=([^&]+)/.exec(location.hash);
  if (linked) {
    history.replaceState(null, "", location.pathname + location.search);
    try { document.getElementById("ticket").value = decodeURIComponent(linked[1]); } catch (e) { /* ignore */ }
    showEnroll("Enrollment ticket received. Name this device and enroll it.");
    document.getElementById("name").focus();
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
})();
