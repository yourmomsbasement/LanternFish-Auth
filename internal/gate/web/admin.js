// Lanternfish Gate admin dashboard. Plain DOM, no third-party code: every
// value from the Gate is inserted as text, never as HTML.
(function () {
  "use strict";

  var csrf = "";
  var view = document.getElementById("view");
  var flashEl = document.getElementById("flash");
  var DAYS = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"];
  var PLATFORMS = ["web", "android", "firetv", "webos", "tizen", "roku"];


  // Help is text-only and shared by all settings, including dynamically added rows.
  var settingHelp = {
  "Admin key": "Use an admin API key to start a dashboard session. The key is cleared from the form after sign-in.",
  "Platform": "Choose the client type that will redeem this single-use enrollment ticket.",
  "Label": "A friendly name to help you recognize the device being enrolled.",
  "Owner": "The person whose permissions and verification factors apply to this device.",
  "Policy": "Choose a policy profile. Global uses the default access rules.",
  "Valid (minutes)": "How long an unused ticket can be redeemed. It stops working after expiry or cancellation.",
  "Public address for links": "The public HTTPS origin used in enrollment links and QR codes. This changes generated links, not the Gate listener.",
  "Reason": "Record why you are making this change or creating this exception.",
  "Ends (optional, your time)": "Optional expiry for the device policy override, entered in your browser’s local time.",
  "Session length (seconds)": "How long a session credential stays valid before renewal. Shorter sessions require more frequent renewal.",
  "Max sessions per device": "Maximum simultaneous sessions for one enrolled device.",
  "Open streams": "Continuity lets existing streams continue after session expiry; strict closes them at expiry.",
  "Bind sessions to the network they were issued on": "Check that a session is used from its approved address or network prefix.",
  "Match": "Exact matches one IP address. Network prefix accepts addresses in the configured subnet.",
  "IPv4 prefix": "Number of matching IPv4 bits. Larger values allow a smaller network; 32 matches one address.",
  "IPv6 prefix": "Number of matching IPv6 bits. Larger values allow a smaller network; 128 matches one address.",
  "New network": "Choose whether an unfamiliar network needs device-key proof, owner verification, or is denied.",
  "Approval lasts (seconds)": "How long an approved network remains remembered before it needs approval again.",
  "Networks remembered": "Maximum approved networks retained for each device.",
  "Only allow access at scheduled times": "Limit access to the weekly windows and date range below; blackouts exclude specific intervals.",
  "Time zone (IANA)": "The named time zone used for weekly access windows, including daylight-saving changes.",
  "From": "Start of this weekly access window in the schedule’s time zone, inclusive.",
  "Until": "End of this weekly window, exclusive. An end before or equal to the start continues into the next day; 24:00 means midnight.",
  "Valid from (your time)": "Optional earliest access date, entered in your browser’s local time.",
  "Valid until (your time)": "Optional end of the access date range, entered in your browser’s local time.",
  "Start (your time)": "Start of the blackout interval, entered in your browser’s local time.",
  "End (your time)": "End of the blackout interval, entered in your browser’s local time.",
  "For a new network, country or address": "Every selected factor is required when a policy rule asks the owner to verify.",
  "To enroll a new device": "Every selected factor is required during enrollment. Selecting none allows enrollment using the ticket and device-key proof.",
  "Pending request lasts (seconds)": "How long the owner has to complete a pending verification request.",
  "Wrong codes allowed": "Maximum failed code attempts before the pending verification is rejected.",
  "Allow authenticator codes": "Allow owners to verify with time-based codes from an authenticator app.",
  "Clock drift (30-second steps)": "Accept codes this many 30-second time steps either side of the current step.",
  "Issue recovery codes": "Allow one-time recovery codes to recover access when normal verification is unavailable.",
  "Allow passkeys and security keys": "Allow WebAuthn verification using registered passkeys or security keys.",
  "Authenticator models": "Choose whether to request and validate authenticator attestation. Trusted models require the configured trust data.",
  "PIN or biometric": "Required demands authenticator user verification. Preferred requests it without requiring support.",
  "Accept synced passkeys (iCloud, Google…)": "Allow backup-eligible passkeys that can sync between devices.",
  "Mode": "Off ignores location rules; record only observes; enforce applies the country restrictions and actions.",
  "Only these countries": "Allow listed ISO country codes. Empty means no country allowlist restriction.",
  "Never these countries": "Deny listed ISO country codes when country enforcement is enabled.",
  "Unknown location": "Action to take when the GeoIP database cannot identify the client’s country.",
  "Country new to the device": "Action to take when a device signs in from an unfamiliar country.",
  "Networks exempt from country rules": "Address ranges that bypass country checks. This does not bypass other authentication rules.",
  "Record reports": "Collect device-signed MAC address reports from clients that support them. A MAC address is not independent identity proof.",
  "Require a report": "Require a current signed report. Browsers cannot supply one; use this only for supported native clients.",
  "When it changes": "Choose the response when a device reports a different MAC address.",
  "Report valid for (seconds)": "Maximum age of a MAC report before it must be refreshed.",
  "edit as JSON": "Switch to the complete policy JSON editor. Preview and publish are still required to apply changes.",
  "Jellyfin address": "Internal HTTP or HTTPS URL the Gate forwards Jellyfin requests to. Empty uses gate.env.",
  "Sign-in host (Jellyfin's public name)": "Public hostname used for browser sign-in and linked application sessions. Enter a hostname, not a URL.",
  "Admin networks (one per line: address or CIDR)": "Restrict dashboard and admin API access by source network. Keep your current address allowed. Empty uses gate.env.",
  "Name": "A friendly name used to identify this application or guest in the dashboard.",
  "Enabled": "Allow this application to receive authenticated traffic through the Gate after saving.",
  "Public hostnames": "Hostnames routed to this application. Each needs DNS pointing to the Gate and valid TLS coverage.",
  "Address behind the Gate": "Internal URL of the application, including its port. The Gate forwards authorized requests here.",
  "Who can use it": "Everyone allows all active owners; Selected owners allows only those checked; Admins only requires an active admin owner.",
  "Owners allowed (none ticked: no one)": "Only checked owners can reach this application. An empty selection denies everyone.",
  "Send the public hostname": "Forward the requested public hostname to the application instead of its internal upstream hostname.",
  "Keep browser sessions alive": "Inject the Gate renewal script into supported HTML pages so browser sessions can renew.",
  "Send Lanternfish identity headers": "Send the device ID and signed Lanternfish identity headers to this backend. Enable for backends that need them.",
  "Container ID": "Proxmox container ID for the Gate. The generated script targets this guest’s firewall configuration.",
  "LAN interface": "Proxmox network interface where public HTTPS traffic reaches the Gate, such as net0.",
  "Internal address": "The Gate’s static address on the isolated backend subnet.",
  "Public HTTPS port": "Inbound TCP port allowed for public HTTPS access to the Gate.",
  "Internal service port": "Private signing-service TCP port. Zero disables the firewall allowance; match the listener in gate.env.",
  "Internal interface": "The Gate’s Proxmox interface connected to the isolated backend subnet.",
  "Internal network": "CIDR of the isolated backend subnet. Guests should have static addresses in this network.",
  "SSH allowed from": "Only these addresses or CIDRs may reach the Gate’s SSH port. Empty permits no SSH in the generated rules.",
  "Answer ping": "Permit inbound ICMP ping requests to the Gate.",
  "Additional LAN networks": "Extra CIDRs to block for isolated guests, including public IPv6 prefixes used on your LAN. Explicit allowances take precedence.",
  "Also block link-local and multicast destinations": "Block link-local and multicast destinations for isolated guests, except explicit allowances. This can affect discovery services.",
  "Type": "Select whether this Proxmox guest is a container or a virtual machine.",
  "ID": "Proxmox VM or container ID. The generated script writes rules for this guest.",
  "Address": "This guest’s static internal IP address, used for firewall rules and anti-spoofing.",
  "Ports": "Comma-separated destination ports allowed by this rule. Include only the ports the service needs.",
  "Interface": "Proxmox network interface on which these guest firewall rules apply.",
  "The Gate reaches it": "Allow the Gate to connect to this guest’s listed service ports.",
  "Internal Jellyfin service access": "Allow this backend to reach the private Jellyfin signing service. It must also be a named authorized client in gate.env.",
  "Keep it off my LAN": "Block private-network destinations except explicit guest, signing-service, or external-target allowances. Internet traffic remains allowed.",
  "Talks to": "Allow outbound connections to selected guests’ listed ports. This is one-way; reverse access needs a separate selection.",
  "Also allow from": "Additional source addresses or CIDRs allowed to reach this guest’s listed ports.",
  "Target address": "One literal IP address for an external destination such as a NAS. Hostnames and CIDRs are not accepted.",
  "Protocol": "Transport protocol for this external-target allowance. Match the service’s TCP or UDP requirements.",
  "Linked owner": "Associate this admin key with an active admin owner for authenticator re-verification of sensitive changes.",
  "let it replace the authenticator app": "Allow the setup link to replace this owner’s existing authenticator registration.",
  "show revoked": "Include devices whose access has been permanently revoked.",
  "authenticator code": "Require an authenticator-app code as part of this verification rule.",
  "passkey": "Require a registered passkey or security key as part of this verification rule.",
  "Profile name": "Name this reusable policy profile. New profiles start as a copy of the global policy.",
  "Owner name": "Name the person who will own devices and verification factors.",
  "Role": "Owner grants ordinary device ownership. Admin identifies an administrator and can satisfy admin-only app access.",
  "Policy scope": "Choose the global policy or a profile to edit. Publishing changes applies them to devices using that scope.",
  "Change reason": "Explain the policy change. This reason is saved with the published policy history.",
  "Audit filter": "Search recorded audit events, for example by event name or device ID. Refresh applies the filter.",
  "Authenticator code": "Enter a current code from the linked admin owner’s authenticator app to confirm sensitive changes.",
  "Policy JSON": "Edit the full policy document. Preview validates it before publishing."
};
  var helpSequence = 0;
  var activeHelp = null;
  function closeHelp() {
    if (activeHelp) {
      activeHelp.tip.hidden = true;
      activeHelp.button.setAttribute("aria-expanded", "false");
      activeHelp = null;
    }
  }
  function helpButton(label, text, controls) {
    var box = document.createElement("span");
    box.className = "setting-help";
    var button = document.createElement("button");
    button.type = "button";
    button.className = "help-button";
    button.textContent = "?";
    button.setAttribute("aria-label", "Help: " + label);
    button.setAttribute("aria-expanded", "false");
    var tip = document.createElement("span");
    tip.id = "setting-help-" + (++helpSequence);
    tip.className = "help-tooltip";
    tip.setAttribute("role", "tooltip");
    tip.textContent = text;
    tip.hidden = true;
    button.setAttribute("aria-describedby", tip.id);
    button.setAttribute("aria-controls", tip.id);
    controls.forEach(function (control) {
      var previous = control.getAttribute("aria-describedby");
      control.setAttribute("aria-describedby", (previous ? previous + " " : "") + tip.id);
    });
    function show() {
      closeHelp();
      tip.hidden = false;
      button.setAttribute("aria-expanded", "true");
      activeHelp = { button: button, tip: tip };
      var rect = button.getBoundingClientRect();
      var width = tip.getBoundingClientRect().width;
      tip.style.left = Math.max(12, Math.min(rect.left, window.innerWidth - width - 12)) + "px";
      var height = tip.getBoundingClientRect().height;
      tip.style.top = Math.max(12, rect.bottom + height + 12 > window.innerHeight ? rect.top - height - 8 : rect.bottom + 8) + "px";
    }
    button.addEventListener("focus", show);
    box.addEventListener("mouseenter", show);
    box.addEventListener("mouseleave", function () { if (document.activeElement !== button) closeHelp(); });
    button.addEventListener("blur", closeHelp);
    button.addEventListener("click", show);
    box.appendChild(button);
    box.appendChild(tip);
    return box;
  }
  document.addEventListener("keydown", function (e) { if (e.key === "Escape") closeHelp(); });
  document.addEventListener("click", function (e) { if (!e.target.closest(".setting-help")) closeHelp(); });
  window.addEventListener("resize", closeHelp);
  document.addEventListener("scroll", closeHelp, true);
  function describeField(el) {
    var label = el.querySelector("label");
    if (!label) return;
    var name = label.textContent.trim();
    var controls = Array.prototype.slice.call(el.querySelectorAll("input, select, textarea"));
    var text = settingHelp[name];
    if (!text) return;
    if (controls.length === 1) {
      if (!controls[0].id) controls[0].id = "setting-" + (++helpSequence);
      label.htmlFor = controls[0].id;
    }
    var heading = document.createElement("div");
    heading.className = "field-heading";
    el.insertBefore(heading, label);
    heading.appendChild(label);
    heading.appendChild(helpButton(name, text, controls));
  }

  // ---- helpers ----

  function h(tag, attrs) {
    var el = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (k) {
        var v = attrs[k];
        if (v === undefined || v === null || v === false) return;
        if (k.slice(0, 2) === "on") el.addEventListener(k.slice(2), v);
        else if (k === "text") el.textContent = v;
        else if (k === "value") el.value = v;
        else if (k === "checked") el.checked = !!v;
        else el.setAttribute(k, v === true ? "" : v);
      });
    }
    for (var i = 2; i < arguments.length; i++) add(el, arguments[i]);
    if (tag === "div" && el.classList.contains("field")) describeField(el);
    if (tag === "label" && el.querySelector("input[type=checkbox]")) {
      var name = el.textContent.trim();
      var text = el.getAttribute("title") || settingHelp[name];
      if (text) {
        el.removeAttribute("title");
        var choice = document.createElement("span");
        choice.className = "setting-choice";
        choice.appendChild(el);
        choice.appendChild(helpButton(name, text, [el.querySelector("input")]));
        return choice;
      }
    }
    return el;
  }
  // add(el, child, child, …): children may be nodes, text, arrays, or empty.
  function add(el) {
    for (var i = 1; i < arguments.length; i++) {
      var c = arguments[i];
      if (c === undefined || c === null || c === false) continue;
      if (Array.isArray(c)) c.forEach(function (x) { add(el, x); });
      else el.appendChild(typeof c === "string" || typeof c === "number" ? document.createTextNode(String(c)) : c);
    }
  }
  // Links from outside data (GitHub's API) must be plain https.
  function safeURL(u) { return /^https:\/\//.test(u || "") ? u : undefined; }
  function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); }

  function flash(msg, isError) {
    flashEl.textContent = msg;
    flashEl.className = isError ? "error" : "";
    flashEl.hidden = !msg;
    if (msg && !isError) setTimeout(function () { if (flashEl.textContent === msg) flashEl.hidden = true; }, 5000);
  }

  function when(t) {
    if (!t) return "—";
    var d = new Date(t);
    return isNaN(d) ? String(t) : d.toLocaleString();
  }

  function api(method, path, body, retried) {
    var opts = { method: method, credentials: "same-origin", headers: {} };
    if (method !== "GET") opts.headers["X-Lanternfish-CSRF"] = csrf;
    if (body !== undefined) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(body);
    }
    return fetch(path, opts).then(function (res) {
      if (res.status === 204) return {};
      return res.json().catch(function () { return {}; }).then(function (data) {
        // 401 means the admin session ended, except a wrong re-verification code.
        if (res.status === 401 && path.indexOf("/session") < 0 && path !== UI + "verify") {
          showSignIn("Your admin session ended. Sign in again.");
          throw new Error("signed out");
        }
        // Sensitive changes need a fresh authenticator code: ask, then retry once.
        if (res.status === 403 && data.error === "recent_verification_required" && !retried) {
          return reverify().then(function () { return api(method, path, body, true); });
        }
        if (!res.ok) {
          var err = new Error(data.detail || data.error || ("HTTP " + res.status));
          err.status = res.status;
          err.data = data;
          throw err;
        }
        return data;
      });
    });
  }
  var V1 = "/_lanternfish/admin/v1/", V2 = "/_lanternfish/admin/v2/", UI = "/_lanternfish/admin/";

  // reverify asks for the linked owner's authenticator code (resolves when
  // accepted, rejects when cancelled).
  function reverify() {
    return new Promise(function (resolve, reject) {
      var code = h("input", { inputmode: "numeric", autocomplete: "one-time-code", pattern: "[0-9 ]{6,8}", maxlength: "8", required: true, "aria-label": "Authenticator code" });
      var msg = h("p", { class: "muted small", text: "This change needs your authenticator code (valid for 5 minutes of changes)." });
      var dlg = h("dialog", { class: "card", oncancel: function () { dlg.remove(); reject(new Error("Not confirmed; nothing was changed.")); } });
      var form = h("form", { onsubmit: function (e) {
        e.preventDefault();
        api("POST", UI + "verify", { code: code.value.replace(/\s/g, "") }).then(function () {
          dlg.close(); dlg.remove(); resolve();
        }, function (err) {
          code.value = "";
          msg.textContent = err.status === 429 ? "Too many wrong codes; wait a few minutes." : "Code not accepted. Try the next one.";
          msg.className = "bad small";
        });
      } }, h("h2", { text: "Confirm it's you" }), msg, h("div", { class: "row" }, code, helpButton("Authenticator code", settingHelp["Authenticator code"], [code]),
        h("button", { type: "submit", text: "Confirm" }),
        h("button", { type: "button", class: "secondary", text: "Cancel", onclick: function () {
          dlg.close(); dlg.remove(); reject(new Error("Not confirmed; nothing was changed."));
        } })));
      add(dlg, form);
      document.body.appendChild(dlg);
      dlg.showModal();
      code.focus();
    });
  }

  function fail(err) {
    if (err && err.message === "signed out") return;
    var msg = err && err.message ? err.message : String(err);
    if (err && err.data && err.data.problems) msg += ": " + err.data.problems.join("; ");
    flash(msg, true);
  }

  // Shared lookups for names in tables and selects.
  var cache = { profiles: [], subjects: [] };
  function loadLookups() {
    return Promise.all([api("GET", V2 + "profiles"), api("GET", V2 + "subjects")]).then(function (r) {
      cache.profiles = r[0].profiles;
      cache.subjects = r[1].subjects;
    });
  }
  function profileName(id) {
    if (!id) return "Global";
    var p = cache.profiles.filter(function (x) { return x.id === id; })[0];
    return p ? p.name : id;
  }
  function subjectName(id) {
    var s = cache.subjects.filter(function (x) { return x.id === id; })[0];
    return s ? s.name : (id || "—");
  }
  function profileSelect(selected, withGlobal) {
    var sel = h("select");
    if (withGlobal !== false) add(sel, h("option", { value: "", text: "Global policy" }));
    cache.profiles.forEach(function (p) { add(sel, h("option", { value: p.id, text: p.name })); });
    sel.value = selected || "";
    return sel;
  }

  // ---- sign-in ----

  var signin = document.getElementById("signin");
  var keyLabel = signin.querySelector("label");
  keyLabel.after(helpButton("Admin key", settingHelp["Admin key"], [document.getElementById("key")]));
  function showSignIn(msg) {
    csrf = "";
    document.getElementById("nav").hidden = true;
    document.getElementById("signout").hidden = true;
    document.getElementById("who").textContent = "";
    clear(view);
    signin.hidden = false;
    flash(msg || "", !!msg);
    document.getElementById("key").focus();
  }
  function signedIn(data) {
    csrf = data.csrf || "";
    signin.hidden = true;
    document.getElementById("key").value = "";
    document.getElementById("nav").hidden = false;
    document.getElementById("signout").hidden = false;
    document.getElementById("who").textContent = "Signed in as " + data.name;
    flash("");
    go(location.hash.slice(1) || "devices");
  }
  signin.addEventListener("submit", function (e) {
    e.preventDefault();
    api("POST", UI + "session", { key: document.getElementById("key").value.trim() })
      .then(signedIn, function (err) { flash(err.message, true); });
  });
  document.getElementById("signout").addEventListener("click", function () {
    api("POST", UI + "logout").then(function () { showSignIn(""); }, fail);
  });

  // ---- navigation ----

  var tabs = {};
  function go(tab) {
    if (!tabs[tab]) tab = "devices";
    if (location.hash.slice(1) !== tab) history.replaceState(null, "", "#" + tab);
    Array.prototype.forEach.call(document.querySelectorAll("nav button"), function (b) {
      if (b.dataset.tab === tab) b.setAttribute("aria-current", "page");
      else b.removeAttribute("aria-current");
    });
    clear(view);
    add(view, h("p", { class: "muted", text: "Loading…" }));
    // A slow tab (Updates asks GitHub) must not replace one opened after it.
    var gen = ++generation;
    loadLookups().then(function () { return gen === generation ? tabs[tab]() : null; }).then(function (content) {
      if (gen !== generation) return;
      clear(view);
      add(view, content);
    }).catch(function (err) { if (gen === generation) fail(err); });
  }
  var generation = 0;
  Array.prototype.forEach.call(document.querySelectorAll("nav button"), function (b) {
    b.addEventListener("click", function () { flash(""); go(b.dataset.tab); });
  });
  function reload() { go(location.hash.slice(1)); }

  // ---- devices ----

  tabs.devices = function () {
    return api("GET", V1 + "devices").then(function (data) {
      data.devices.forEach(function (d) { deviceNames[d.id] = d.name; });
      var showRevoked = h("input", { type: "checkbox", id: "showrev" });
      var table = h("table", null, h("thead", null, h("tr", null,
        ["Device", "Owner", "Policy", "Networks", "Sessions", "Last sign-in", ""].map(function (t) { return h("th", { text: t }); }))));
      var body = h("tbody");
      add(table, body);
      function render() {
        clear(body);
        data.devices.filter(function (d) { return showRevoked.checked || !d.revoked_at; }).forEach(function (d) {
          var prof = profileSelect(d.profile_id);
          prof.setAttribute("aria-label", "Policy for " + d.name);
          var profHelp = helpButton("Policy for " + d.name, settingHelp.Policy, [prof]);
          prof.disabled = !!d.revoked_at;
          prof.addEventListener("change", function () {
            api("PUT", V2 + "devices/" + encodeURIComponent(d.id) + "/profile", { profile_id: prof.value })
              .then(function () { flash("Moved " + d.name + " to " + profileName(prof.value) + "."); }, fail);
          });
          var nets = h("div", { class: "chips" });
          (d.networks || []).forEach(function (n) {
            add(nets, h("span", { class: "chip", title: n.method + ", until " + when(n.expires_at) },
              h("span", { class: "mono", text: n.network }),
              h("button", { class: "link", "aria-label": "Remove network " + n.network, text: "×", onclick: function () {
                if (!confirm("Remove " + n.network + " from " + d.name + "? Its sessions there end now.")) return;
                api("DELETE", V2 + "devices/" + encodeURIComponent(d.id) + "/networks/" + encodeURIComponent(n.id))
                  .then(reload, fail);
              } })));
          });
          if (!d.networks || !d.networks.length) add(nets, h("span", { class: "muted small", text: "none" }));
          var status = d.revoked_at
            ? h("span", { class: "bad", text: d.revocation_unsaved ? "revoked (NOT SAVED: revoke again)" : "revoked " + when(d.revoked_at) })
            : h("button", { class: "danger", text: "Revoke", onclick: function () {
              if (!confirm("Revoke " + d.name + "? It is locked out immediately and must be enrolled again.")) return;
              api("POST", V1 + "devices/" + encodeURIComponent(d.id) + "/revoke").then(function () {
                flash("Revoked " + d.name + "."); reload();
              }, fail);
            } });
          var detail = h("tr", { hidden: true }, h("td", { colspan: "7" }));
          var badges = h("div", { class: "chips" },
            d.suspended ? h("span", { class: "chip bad", text: "suspended: " + d.suspended.replace(/_/g, " ") }) : null,
            d.override ? h("span", { class: "chip", text: "own policy" + (d.override.expires_at ? " until " + when(d.override.expires_at) : "") }) : null,
            d.parent_id ? h("span", { class: "chip", text: "linked for " + d.linked_host }) : null);
          add(body, h("tr", null,
            h("td", null, h("strong", { text: d.name || "(unnamed)" }), h("div", { class: "muted small" },
              d.platform + " · ", h("span", { class: "mono", text: d.id }), " · enrolled " + when(d.created_at) + " from " + d.enrolled_from),
              badges,
              h("button", { class: "link small", text: "Details", "aria-expanded": "false", onclick: function (e) {
                detail.hidden = !detail.hidden;
                e.target.setAttribute("aria-expanded", String(!detail.hidden));
                if (!detail.hidden && !detail.firstChild.firstChild) add(detail.firstChild, deviceDetail(d));
              } })),
            h("td", { text: subjectName(d.subject_id) }),
            h("td", null, prof, profHelp, h("div", { class: "muted small", text: "v" + d.policy_version })),
            h("td", null, nets),
            h("td", { text: String(d.live_sessions || 0) }),
            h("td", { text: when(d.last_auth_at) }),
            h("td", null, status)), detail);
        });
        if (!body.firstChild) add(body, h("tr", null, h("td", { colspan: "7", class: "muted", text: "No devices yet. Create a ticket to enroll one." })));
      }
      showRevoked.addEventListener("change", render);
      render();
      return h("div", { class: "card" }, h("div", { class: "row" }, h("h2", { text: "Devices" }),
        h("label", { class: "small" }, showRevoked, " show revoked")), table);
    });
  };

  var deviceNames = {};
  function deviceName(id) { return deviceNames[id] || id; }

  // deviceDetail: key, location, MAC evidence, own policy and recovery actions.
  function deviceDetail(d) {
    var path = V2 + "devices/" + encodeURIComponent(d.id);
    var box = h("div", { class: "detail" });
    function kv(k, v) { return [h("dt", { text: k }), h("dd", null, v)]; }
    add(box, h("dl", null,
      kv("Key fingerprint", h("span", { class: "mono", text: d.key_fingerprint || "—" })),
      d.parent_id ? kv("Linked to", h("span", null, deviceName(d.parent_id) + " for " + d.linked_host +
        " (follows that device: revoking it revokes this too)")) : null,
      kv("Countries", d.countries.length ? d.countries.map(function (c) {
        return (c.country || "unknown (" + c.network + ")") + " via " + c.method + ", until " + when(c.expires_at);
      }).join("; ") : "none recorded"),
      kv("Network addresses", d.macs.length ? d.macs.map(function (m) {
        return m.interface_kind + (m.randomized === "yes" ? " (randomized)" : "") + ", last reported " + when(m.last_seen);
      }).join("; ") : (d.platform === "web" ? "browsers can't report one" : "none reported")),
      kv("Own policy", d.override ? "v" + d.override.policy_version + " by " + d.override.set_by + ": " + d.override.reason +
        (d.override.expires_at ? " (until " + when(d.override.expires_at) + ")" : "") : "none (uses " + profileName(d.profile_id) + ")")));

    var actions = h("div", { class: "row" });
    add(box, actions);
    if (d.revoked_at) return box;
    if (d.suspended) {
      add(actions, h("button", { class: "secondary", text: "Lift suspension", onclick: function () {
        if (!confirm("Let " + d.name + " sign in again? Its MAC report changed; resetting enrollment is usually safer.")) return;
        api("POST", path + "/unsuspend").then(function () { flash("Suspension lifted."); reload(); }, fail);
      } }));
    }
    add(actions, h("button", { class: "secondary", text: d.override ? "Edit own policy" : "Give it its own policy", onclick: function (e) {
      e.target.disabled = true;
      overrideEditor(d, path).then(function (el) { add(box, el); }, function (err) { e.target.disabled = false; fail(err); });
    } }));
    if (d.override) {
      add(actions, h("button", { class: "secondary", text: "Remove own policy", onclick: function () {
        api("DELETE", path + "/override").then(function () { flash(d.name + " uses " + profileName(d.profile_id) + " again."); reload(); }, fail);
      } }));
    }
    add(actions, h("button", { class: "danger", text: "Reset enrollment", onclick: function () {
      if (!confirm("Reset " + d.name + "? Its key is revoked now and a one-time ticket is issued to enroll it again.")) return;
      api("POST", path + "/reset-enrollment").then(function (t) {
        clear(actions);
        add(actions, ticketBox(t));
      }, fail);
    } }));
    return box;
  }

  function overrideEditor(d, path) {
    var load = d.override
      ? api("GET", V2 + "policy/history?scope=" + encodeURIComponent("device:" + d.id)).then(function (r) {
        return r.history.filter(function (x) { return x.version === d.override.policy_version; })[0] || r.history[0];
      })
      : api("GET", V2 + "policy").then(function (r) {
        var p = r.profiles.filter(function (x) { return x.scope === d.profile_id; })[0];
        return p || r.global;
      });
    return load.then(function (rec) {
      var form = policyForm(rec.policy);
      var reason = h("input", { placeholder: "why (required)", maxlength: "64", size: "30", value: d.override ? d.override.reason : "" });
      var until = h("input", { type: "datetime-local" });
      return h("div", { class: "card" }, h("h3", { text: "Own policy for " + d.name }),
        h("p", { class: "muted small", text: "Applies to this device only, ahead of its profile and the global policy." }),
        form.el,
        h("div", { class: "row" }, h("div", { class: "field" }, h("label", { text: "Reason" }), reason),
          h("div", { class: "field" }, h("label", { text: "Ends (optional, your time)" }), until),
          h("button", { text: "Save", onclick: function () {
            var body = { policy: form.value(), reason: reason.value };
            if (until.value) body.expires_at = new Date(until.value).toISOString();
            api("PUT", path + "/override", body).then(function () { flash("Saved " + d.name + "'s own policy."); reload(); }, fail);
          } })));
    });
  }

  // ticketBox shows a one-time ticket (and its QR code).
  function ticketBox(t) {
    var link = publicOrigin().replace(/\/+$/, "") + "/_lanternfish/#ticket=" + encodeURIComponent(t.ticket);
    var isWeb = t.platform === "web";
    var box = h("div", { class: "card ticket" }, h("div", null,
      h("h3", { text: "Ticket for " + (t.label || t.platform) }),
      h("p", { class: "small" }, "Shown once. Expires " + when(t.expires_at) + ". Single use."),
      h("div", { class: "row" }, h("code", { text: t.ticket }), copyButton(t.ticket)),
      isWeb ? h("div", { class: "row" }, h("code", { text: link }), copyButton(link)) :
        h("p", { class: "small muted", text: "Enter this ticket in the Lanternfish app on the device (or scan the QR code with it)." })));
    drawQR(isWeb ? link : t.ticket).then(function (svg) { add(box, svg); }, fail);
    return box;
  }

  // ---- tickets ----

  function publicOrigin() {
    try { return localStorage.getItem("lf-public-origin") || location.origin; } catch (e) { return location.origin; }
  }

  function drawQR(text) {
    return api("POST", UI + "v2/qr", { text: text }).then(function (q) {
      var ns = "http://www.w3.org/2000/svg", n = q.size + 8;
      var svg = document.createElementNS(ns, "svg");
      svg.setAttribute("viewBox", "0 0 " + n + " " + n);
      svg.setAttribute("class", "qr");
      svg.setAttribute("role", "img");
      svg.setAttribute("aria-label", "QR code of the enrollment link");
      svg.setAttribute("shape-rendering", "crispEdges");
      var d = "";
      q.rows.forEach(function (row, y) {
        for (var x = 0; x < row.length; x++) if (row.charAt(x) === "1") d += "M" + (x + 4) + " " + (y + 4) + "h1v1h-1z";
      });
      var path = document.createElementNS(ns, "path");
      path.setAttribute("d", d);
      path.setAttribute("fill", "#000");
      svg.appendChild(path);
      return svg;
    });
  }

  function copyButton(text) {
    return h("button", { class: "secondary", text: "Copy", onclick: function (e) {
      var b = e.target;
      navigator.clipboard.writeText(text).then(function () { b.textContent = "Copied"; }, function () { b.textContent = "Copy failed"; });
    } });
  }

  tabs.tickets = function () {
    return api("GET", V1 + "tickets").then(function (data) {
      var platform = h("select", null, PLATFORMS.map(function (p) { return h("option", { value: p, text: p }); }));
      var label = h("input", { maxlength: "64", placeholder: "e.g. Living room TV" });
      var owner = h("select", null, cache.subjects.filter(function (s) { return s.status === "active"; })
        .map(function (s) { return h("option", { value: s.id, text: s.name }); }));
      var prof = profileSelect("");
      var ttl = h("input", { type: "number", min: "1", max: "1440", value: "60", class: "small" });
      var origin = h("input", { value: publicOrigin(), size: "32", title: "The address phones will use (your public domain)" });
      origin.addEventListener("change", function () { try { localStorage.setItem("lf-public-origin", origin.value.replace(/\/+$/, "")); } catch (e) { /* not kept */ } });
      var result = h("div");

      var form = h("form", { class: "card", onsubmit: function (e) {
        e.preventDefault();
        api("POST", V1 + "tickets", { platform: platform.value, label: label.value, subject_id: owner.value,
          profile_id: prof.value, ttl_seconds: Math.round(Number(ttl.value) * 60) }).then(function (t) {
          clear(result);
          var base = origin.value.replace(/\/+$/, "");
          var link = base + "/_lanternfish/#ticket=" + encodeURIComponent(t.ticket);
          var isWeb = t.platform === "web";
          var info = h("div", null,
            h("h3", { text: "Ticket for " + (t.label || t.platform) }),
            h("p", { class: "small" }, "Shown once. Expires " + when(t.expires_at) + ". Single use."),
            h("div", { class: "row" }, h("code", { text: t.ticket }), copyButton(t.ticket)),
            isWeb ? h("div", null, h("p", { class: "small muted", text: "Or scan on the phone/browser to enroll (the ticket is in the link's #fragment, which is never sent to a server):" }),
              h("div", { class: "row" }, h("code", { text: link }), copyButton(link))) :
              h("p", { class: "small muted", text: "Enter this ticket in the Lanternfish app on the device (or scan the QR code with it)." }));
          var box = h("div", { class: "card ticket" }, info);
          add(result, box);
          drawQR(isWeb ? link : t.ticket).then(function (svg) { add(box, svg); }, fail);
          label.value = "";
          refreshList();
        }, fail);
      } },
        h("h2", { text: "New enrollment ticket" }),
        h("div", { class: "row" },
          h("div", { class: "field" }, h("label", { text: "Platform" }), platform),
          h("div", { class: "field" }, h("label", { text: "Label" }), label),
          h("div", { class: "field" }, h("label", { text: "Owner" }), owner),
          h("div", { class: "field" }, h("label", { text: "Policy" }), prof),
          h("div", { class: "field" }, h("label", { text: "Valid (minutes)" }), ttl)),
        h("div", { class: "row" }, h("div", { class: "field" }, h("label", { text: "Public address for links" }), origin),
          h("button", { type: "submit", text: "Create ticket" })));

      var list = h("div", { class: "card" });
      function renderList(tickets) {
        clear(list);
        add(list, h("h2", { text: "Pending tickets" }));
        if (!tickets.length) { add(list, h("p", { class: "muted", text: "None." })); return; }
        add(list, h("table", null, h("thead", null, h("tr", null, ["Label", "Platform", "Owner", "Policy", "Created", "Expires", ""]
          .map(function (t) { return h("th", { text: t }); }))), h("tbody", null, tickets.map(function (t) {
          return h("tr", null, h("td", { text: t.label || "—" }), h("td", { text: t.platform }), h("td", { text: subjectName(t.subject_id) }),
            h("td", { text: profileName(t.profile_id) }), h("td", { text: when(t.created_at) + " by " + t.created_by }),
            h("td", { text: when(t.expires_at) }),
            h("td", null, h("button", { class: "danger", text: "Cancel", onclick: function () {
              api("DELETE", V1 + "tickets/" + encodeURIComponent(t.id)).then(refreshList, fail);
            } })));
        }))));
      }
      function refreshList() { api("GET", V1 + "tickets").then(function (d) { renderList(d.tickets); }, fail); }
      renderList(data.tickets);
      return [form, result, list];
    });
  };

  // ---- policy ----

  function policyForm(policy) {
    var p = JSON.parse(JSON.stringify(policy));
    var s = p.session, ip = p.ip, sc = p.schedule;
    sc.weekly_windows = sc.weekly_windows || [];
    sc.blackout_intervals = sc.blackout_intervals || [];
    var root = h("div");
    var week = h("div");

    function num(obj, key, attrs) {
      var el = h("input", Object.assign({ type: "number", value: obj[key] }, attrs || {}));
      el.addEventListener("input", function () { obj[key] = Number(el.value); });
      return el;
    }
    function pick(obj, key, options, onchange) {
      var el = h("select", null, options.map(function (o) { return h("option", { value: o[0], text: o[1] }); }));
      el.value = obj[key];
      el.addEventListener("change", function () { obj[key] = el.value; if (onchange) onchange(); });
      return el;
    }
    function check(obj, key, onchange) {
      var el = h("input", { type: "checkbox", checked: obj[key] });
      el.addEventListener("change", function () { obj[key] = el.checked; if (onchange) onchange(); });
      return el;
    }
    function field(label, el, hint) {
      return h("div", { class: "field" }, h("label", { text: label }), el, hint ? h("span", { class: "muted small", text: hint }) : null);
    }
    // datetime-local in the browser's time zone <-> RFC 3339
    function localInput(iso, onchange) {
      var el = h("input", { type: "datetime-local" });
      if (iso) {
        var d = new Date(iso);
        el.value = new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
      }
      el.addEventListener("change", function () { onchange(el.value ? new Date(el.value).toISOString() : null); });
      return el;
    }

    var winBox = h("div"), blackBox = h("div");
    function renderWindows() {
      clear(winBox);
      sc.weekly_windows.forEach(function (w, i) {
        var days = h("span", { class: "days" }, DAYS.map(function (d) {
          var c = h("input", { type: "checkbox", checked: w.days.indexOf(d) >= 0 });
          c.addEventListener("change", function () {
            w.days = DAYS.filter(function (x, j) { return days.querySelectorAll("input")[j].checked; });
            renderWeek();
          });
          return h("label", { title: "Include " + d + " in this weekly access window." }, c, d);
        }));
        var start = h("input", { type: "time", value: w.start, step: "60" });
        var end = h("input", { value: w.end, size: "5", placeholder: "HH:MM", pattern: "[0-2][0-9]:[0-5][0-9]", title: "HH:MM, or 24:00 for midnight at the end of the day" });
        start.addEventListener("change", function () { w.start = start.value; renderWeek(); });
        end.addEventListener("change", function () { w.end = end.value; renderWeek(); });
        add(winBox, h("div", { class: "row" }, days, field("From", start), field("Until", end),
          h("button", { type: "button", class: "danger", text: "Remove", onclick: function () { sc.weekly_windows.splice(i, 1); renderWindows(); } })));
      });
      renderWeek();
    }
    function renderBlackouts() {
      clear(blackBox);
      sc.blackout_intervals.forEach(function (b, i) {
        var reason = h("input", { value: b.reason || "", placeholder: "reason", maxlength: "64" });
        reason.addEventListener("input", function () { b.reason = reason.value; });
        add(blackBox, h("div", { class: "row" },
          field("Start (your time)", localInput(b.start, function (v) { b.start = v; })),
          field("End (your time)", localInput(b.end, function (v) { b.end = v; })),
          field("Reason", reason),
          h("button", { type: "button", class: "danger", text: "Remove", onclick: function () { sc.blackout_intervals.splice(i, 1); renderBlackouts(); } })));
      });
    }
    function minutes(t) { var m = /^(\d\d):(\d\d)$/.exec(t || ""); return m ? Number(m[1]) * 60 + Number(m[2]) : -1; }
    function renderWeek() {
      clear(week);
      if (!sc.enabled) { add(week, h("p", { class: "muted small", text: "Schedule off: access at any time." })); return; }
      var on = DAYS.map(function () { return []; });
      sc.weekly_windows.forEach(function (w) {
        var a = minutes(w.start), b = minutes(w.end);
        if (a < 0 || b < 0) return;
        w.days.forEach(function (d) {
          var i = DAYS.indexOf(d);
          if (b > a) on[i].push([a, b]);
          else { on[i].push([a, 1440]); if (b > 0) on[(i + 1) % 7].push([0, b]); }
        });
      });
      var grid = h("div", { class: "week", "aria-label": "Allowed times by half hour, in " + sc.timezone });
      add(grid, h("span"), h("div", { class: "hours" }, ["0", "6", "12", "18", "24"].map(function (x) { return h("span", { text: x }); })));
      DAYS.forEach(function (d, i) {
        add(grid, h("span", { text: d }));
        for (var c = 0; c < 48; c++) {
          var mid = c * 30 + 15;
          var allowed = on[i].some(function (s) { return mid >= s[0] && mid < s[1]; });
          add(grid, h("span", { class: allowed ? "c on" : "c", title: d + " " + String(Math.floor(c / 2)).padStart(2, "0") + ":" + (c % 2 ? "30" : "00") }));
        }
      });
      add(week, h("p", { class: "muted small", text: "Weekly access in " + sc.timezone + " (green = allowed). Blackouts and the date range apply on top." }), grid);
    }

    var schedBody = h("div");
    function renderSchedule() {
      schedBody.hidden = !sc.enabled;
      renderWeek();
    }

    add(root,
      h("h3", { text: "Sessions" }),
      h("div", { class: "row" },
        field("Session length (seconds)", num(s, "ttl_seconds", { min: 60, max: 86400 }), "60–86400; 300 recommended"),
        field("Max sessions per device", num(s, "max_per_device", { min: 1, max: 64 })),
        field("Open streams", pick(s, "stream_expiry_mode", [["continuity", "keep playing past session end"], ["strict", "close at session end"]]))),
      h("h3", { text: "Network binding" }),
      h("div", { class: "row" },
        h("label", null, check(ip, "enabled"), " Bind sessions to the network they were issued on"),
        field("Match", pick(ip, "match", [["prefix", "network prefix"], ["exact", "exact address"]])),
        field("IPv4 prefix", num(ip, "ipv4_prefix_len", { min: 8, max: 32 }), "32 = exact address"),
        field("IPv6 prefix", num(ip, "ipv6_prefix_len", { min: 32, max: 128 }), "64 recommended")),
      h("div", { class: "row" },
        field("New network", pick(ip, "on_change", [["key_proof", "allow after a fresh device-key signature"],
          ["additional_verification", "ask the owner to verify (see below)"], ["deny", "deny (re-enroll to add networks)"]])),
        field("Approval lasts (seconds)", num(ip, "approval_ttl_seconds", { min: 3600, max: 2592000 })),
        field("Networks remembered", num(ip, "remembered_networks", { min: 1, max: 10 }))),
      h("h3", { text: "Schedule" }),
      h("div", { class: "row" },
        h("label", null, check(sc, "enabled", renderSchedule), " Only allow access at scheduled times"),
        field("Time zone (IANA)", (function () {
          var tz = h("input", { value: sc.timezone, placeholder: "America/Chicago" });
          tz.addEventListener("change", function () { sc.timezone = tz.value.trim(); renderWeek(); });
          return tz;
        })())),
      schedBody);
    add(schedBody,
      h("p", { class: "muted small", text: "Windows are [from, until) in the schedule's time zone. An end at or before the start runs past midnight; 24:00 is the end of the day." }),
      winBox,
      h("button", { type: "button", class: "secondary", text: "Add window", onclick: function () {
        sc.weekly_windows.push({ days: ["mon", "tue", "wed", "thu", "fri"], start: "08:00", end: "22:00" }); renderWindows();
      } }),
      h("h3", { text: "Date range" }),
      h("div", { class: "row" },
        field("Valid from (your time)", localInput(sc.valid_from, function (v) { sc.valid_from = v; })),
        field("Valid until (your time)", localInput(sc.valid_until, function (v) { sc.valid_until = v; }))),
      h("h3", { text: "Blackouts" }),
      blackBox,
      h("button", { type: "button", class: "secondary", text: "Add blackout", onclick: function () {
        var now = new Date();
        sc.blackout_intervals.push({ start: now.toISOString(), end: new Date(now.getTime() + 3600000).toISOString(), reason: "" });
        renderBlackouts();
      } }));
    // ---- verification, factors, location, MAC ----
    var v = p.verification, totp = p.totp, wa = p.webauthn, geo = p.geo, mac = p.mac;
    function factors(obj, key) {
      obj[key] = obj[key] || [];
      return h("span", { class: "days" }, [["totp", "authenticator code"], ["webauthn", "passkey"]].map(function (f) {
        var c = h("input", { type: "checkbox", checked: obj[key].indexOf(f[0]) >= 0 });
        c.addEventListener("change", function () {
          obj[key] = obj[key].filter(function (x) { return x !== f[0]; });
          if (c.checked) obj[key].push(f[0]);
        });
        return h("label", null, c, f[1]);
      }));
    }
    function list(obj, key, placeholder) {
      var el = h("input", { value: (obj[key] || []).join(", "), placeholder: placeholder, size: "30" });
      el.addEventListener("change", function () {
        obj[key] = el.value.split(/[\s,]+/).filter(Boolean).map(function (x) { return x.indexOf("/") >= 0 ? x : x.toUpperCase(); });
      });
      return el;
    }
    var ACTIONS = [["deny", "deny"], ["additional_verification", "ask the owner to verify"], ["observe", "allow and record"]];
    add(root,
      h("h3", { text: "Additional verification" }),
      h("p", { class: "muted small", text: "When a rule asks for verification, the device waits while its owner proves it's them. All the checked factors are needed." }),
      h("div", { class: "row" },
        field("For a new network, country or address", factors(v, "new_network_required_all")),
        field("To enroll a new device", factors(v, "enrollment_required_all"), "none = a ticket alone enrolls")),
      h("div", { class: "row" },
        field("Pending request lasts (seconds)", num(v, "pending_ttl_seconds", { min: 60, max: 1800 })),
        field("Wrong codes allowed", num(v, "max_failed_code_attempts", { min: 1, max: 10 }))),
      h("h3", { text: "Authenticator app (TOTP)" }),
      h("div", { class: "row" },
        h("label", null, check(totp, "enabled"), " Allow authenticator codes"),
        field("Clock drift (30-second steps)", num(totp, "allowed_step_drift", { min: 0, max: 2 }), "1 recommended"),
        h("label", null, check(totp, "recovery_codes"), " Issue recovery codes")),
      h("h3", { text: "Passkeys (WebAuthn)" }),
      h("div", { class: "row" },
        h("label", null, check(wa, "enabled"), " Allow passkeys and security keys"),
        field("Authenticator models", pick(wa, "attestation", [["none", "any (don't ask)"], ["collect_if_available", "any, record the model"],
          ["require_trusted", "only FIDO-certified models"]])),
        field("PIN or biometric", pick(wa, "user_verification", [["required", "required"], ["preferred", "preferred"]])),
        h("label", null, check(wa, "allow_backup_eligible"), " Accept synced passkeys (iCloud, Google…)")),
      h("h3", { text: "Location (country)" }),
      h("p", { class: "muted small", text: "From a local GeoIP database. VPNs and mobile networks often show the wrong country: use as a signal, not proof." }),
      h("div", { class: "row" },
        field("Mode", pick(geo, "mode", [["off", "off"], ["observe", "record only"], ["enforce", "enforce"]])),
        field("Only these countries", list(geo, "country_allowlist", "US, CA"), "ISO codes; empty = any"),
        field("Never these countries", list(geo, "country_denylist", "e.g. KP"))),
      h("div", { class: "row" },
        field("Unknown location", pick(geo, "unknown_action", ACTIONS)),
        field("Country new to the device", pick(geo, "new_country_action", ACTIONS)),
        field("Networks exempt from country rules", list(geo, "exempt_networks", "192.168.0.0/16"))),
      h("h3", { text: "Network address (MAC) reports" }),
      h("p", { class: "muted small", text: "Only the Lanternfish apps can report one (signed with the device key); browsers can't. Requiring a report belongs on a profile for TVs and apps." }),
      h("div", { class: "row" },
        h("label", null, check(mac, "collect"), " Record reports"),
        h("label", null, check(mac, "require_report"), " Require a report"),
        field("When it changes", pick(mac, "on_change", [["observe", "allow and record"], ["additional_verification", "ask the owner to verify"],
          ["reenroll", "suspend the device"]])),
        field("Report valid for (seconds)", num(mac, "max_observation_age_seconds", { min: 60, max: 86400 }))));
    add(root, h("h3", { text: "Preview" }), week);
    renderWindows();
    renderBlackouts();
    renderSchedule();
    // Each policy category has its own boundary, without changing its controls.
    var section;
    Array.prototype.slice.call(root.childNodes).forEach(function (node) {
      if (node.nodeName === "H3") {
        section = h("section", { class: "settings-section" });
        root.appendChild(section);
      }
      if (section) section.appendChild(node);
    });
    return { el: root, value: function () { return p; } };
  }

  tabs.policy = function () {
    return api("GET", V2 + "policy").then(function (data) {
      var scopes = [{ id: "global", name: "Global policy", rec: data.global }].concat(data.profiles.map(function (r) {
        return { id: r.scope, name: "Profile: " + r.profile.name, rec: r };
      }));
      var scopeSel = h("select", null, scopes.map(function (s) { return h("option", { value: s.id, text: s.name }); }));
      try { scopeSel.value = sessionStorage.getItem("lf-scope") || "global"; } catch (e) { /* default */ }
      if (!scopeSel.value) scopeSel.value = "global";
      var holder = h("div"), meta = h("p", { class: "muted small" }), previewBox = h("div"), form = null;
      var jsonMode = h("input", { type: "checkbox" });
      var json = h("textarea", { spellcheck: "false", "aria-label": "Policy JSON" });
      var jsonHelp = helpButton("Policy JSON", settingHelp["Policy JSON"], [json]);
      var reason = h("input", { placeholder: "why (recorded in the history)", size: "40", maxlength: "64" });
      var current = null;

      function scope() { return scopes.filter(function (s) { return s.id === scopeSel.value; })[0]; }
      function load(policy) {
        clear(holder); clear(previewBox);
        form = policyForm(policy);
        json.value = JSON.stringify(policy, null, 2);
        add(holder, jsonMode.checked ? [jsonHelp, json] : form.el);
      }
      function value() {
        if (jsonMode.checked) return JSON.parse(json.value);
        return form.value();
      }
      function select() {
        try { sessionStorage.setItem("lf-scope", scopeSel.value); } catch (e) { /* not kept */ }
        current = scope().rec;
        clear(meta);
        add(meta, "Version " + current.version + ", published " + when(current.published_at) + " by " + current.editor + ": " + current.reason);
        load(current.policy);
      }
      scopeSel.addEventListener("change", select);
      jsonMode.addEventListener("change", function () {
        try {
          if (jsonMode.checked) json.value = JSON.stringify(form.value(), null, 2);
          else form = policyForm(JSON.parse(json.value));
        } catch (e) { flash("The JSON isn't valid: " + e.message, true); jsonMode.checked = !jsonMode.checked; return; }
        clear(holder);
        add(holder, jsonMode.checked ? [jsonHelp, json] : form.el);
      });

      function preview() {
        var pol;
        try { pol = value(); } catch (e) { flash("The JSON isn't valid: " + e.message, true); return Promise.reject(e); }
        return api("POST", V2 + "policy/preview", { scope: scopeSel.value, policy: pol }).then(function (r) {
          clear(previewBox);
          if (!r.valid) {
            add(previewBox, h("div", { class: "card" }, h("strong", { class: "bad", text: "Not valid:" }),
              h("ul", null, r.problems.map(function (x) { return h("li", { text: x }); }))));
            return false;
          }
          add(previewBox, h("div", { class: "card" },
            h("strong", { class: "ok", text: "Valid." }),
            h("p", { text: r.devices_in_scope + " device(s) use this policy." }),
            r.devices_blocked_now_by_schedule.length ? h("p", { class: "bad", text: r.devices_blocked_now_by_schedule.length + " would be blocked right now by the schedule." }) : null,
            r.devices_needing_network_approval.length ? h("p", { text: r.devices_needing_network_approval.length + " would need to approve their network on next sign-in." }) : null,
            r.step_up_summary ? h("p", null, "Additional verification asks for: ", h("strong", { text: r.step_up_summary })) : null,
            Object.keys(r.owners_missing_factors || {}).length ? h("p", { class: "bad", text: "Owners who couldn't verify yet (set up their factors on the Owners tab first): " +
              Object.keys(r.owners_missing_factors).map(function (id) {
                return subjectName(id) + " (needs " + r.owners_missing_factors[id].map(function (f) { return f === "totp" ? "authenticator app" : "passkey"; }).join(" and ") + ")";
              }).join(", ") }) : null,
            (r.warnings || []).map(function (w) { return h("p", { class: "bad", text: w }); }),
            r.schedule_changes && r.schedule_changes.length ? h("div", null, h("p", { class: "small muted", text: "Upcoming changes:" }),
              h("ul", { class: "small" }, r.schedule_changes.map(function (c) { return h("li", { text: c.local + ": access " + c.access }); }))) : null));
          return true;
        }, function (err) { fail(err); return false; });
      }
      function publish() {
        preview().then(function (ok) {
          if (!ok) return;
          if (!confirm("Publish this policy for " + scope().name + "? It applies immediately, including to open streams.")) return;
          api("PUT", V2 + "policy", { scope: scopeSel.value, expected_version: current.version, reason: reason.value, policy: value() })
            .then(function (rec) { flash("Published version " + rec.version + "."); reason.value = ""; reload(); }, function (err) {
              if (err.status === 409) flash("Someone else published a newer version (" + err.data.current_version + "). Reload to see it before publishing.", true);
              else fail(err);
            });
        });
      }

      var histBox = h("details", { ontoggle: function (e) {
        if (!e.target.open || e.target.dataset.loaded) return;
        e.target.dataset.loaded = "1";
        api("GET", V2 + "policy/history?scope=" + encodeURIComponent(scopeSel.value)).then(function (hdata) {
          add(e.target, h("table", null, h("tbody", null, hdata.history.map(function (r) {
            return h("tr", null, h("td", { text: "v" + r.version }), h("td", { text: when(r.published_at) }),
              h("td", { text: r.editor }), h("td", { text: r.reason }),
              h("td", null, h("button", { class: "secondary", text: "Load", onclick: function () { load(r.policy); flash("Loaded v" + r.version + " into the editor; publish to restore it."); } })));
          }))));
        }, fail);
      } }, h("summary", { text: "History" }));

      select();
      return h("div", { class: "card" },
        h("div", { class: "row" }, h("h2", { text: "Access policy" }), h("div", { class: "field" }, h("label", { text: "Policy scope" }), scopeSel),
          h("button", { type: "button", class: "secondary", text: "Load recommended", onclick: function () {
            api("GET", V2 + "policy/recommended").then(function (r) { load(r.policy); flash("Recommended policy loaded; review and publish."); }, fail);
          } }),
          h("label", { class: "small" }, jsonMode, " edit as JSON")),
        meta, holder,
        h("div", { class: "row" }, h("button", { type: "button", class: "secondary", text: "Preview", onclick: preview }),
          h("div", { class: "field" }, h("label", { text: "Change reason" }), reason), h("button", { type: "button", text: "Publish", onclick: publish })),
        previewBox, histBox);
    });
  };

  // ---- profiles ----

  tabs.profiles = function () {
    var name = h("input", { placeholder: "e.g. Kids", maxlength: "64", required: true });
    return Promise.resolve([
      h("form", { class: "card", onsubmit: function (e) {
        e.preventDefault();
        api("POST", V2 + "profiles", { name: name.value }).then(function () { flash("Profile created as a copy of the global policy. Edit it on the Policy tab."); reload(); }, fail);
      } }, h("h2", { text: "New profile" }), h("div", { class: "row" }, h("div", { class: "field" }, h("label", { text: "Profile name" }), name), h("button", { type: "submit", text: "Create" }))),
      h("div", { class: "card" }, h("h2", { text: "Profiles" }), cache.profiles.length ? h("table", null,
        h("thead", null, h("tr", null, ["Name", "Devices", "Policy version", "Created", ""].map(function (t) { return h("th", { text: t }); }))),
        h("tbody", null, cache.profiles.map(function (p) {
          return h("tr", null, h("td", { text: p.name }), h("td", { text: String(p.devices) }), h("td", { text: "v" + p.policy_version }),
            h("td", { text: when(p.created_at) }),
            h("td", null, h("button", { class: "secondary", text: "Edit policy", onclick: function () {
              try { sessionStorage.setItem("lf-scope", p.id); } catch (e) { /* default */ }
              go("policy");
            } }), " ", h("button", { class: "danger", text: "Delete", onclick: function () {
              if (!confirm("Delete profile " + p.name + "? Its " + p.devices + " device(s) move to the global policy.")) return;
              api("DELETE", V2 + "profiles/" + encodeURIComponent(p.id)).then(reload, fail);
            } })));
        }))) : h("p", { class: "muted", text: "No profiles. Devices use the global policy." }))
    ]);
  };

  // ---- owners ----

  tabs.owners = function () {
    var name = h("input", { placeholder: "e.g. Alex", maxlength: "64", required: true });
    var role = h("select", null, h("option", { value: "owner", text: "owner" }), h("option", { value: "admin", text: "admin" }));
    return Promise.resolve([
      h("form", { class: "card", onsubmit: function (e) {
        e.preventDefault();
        api("POST", V2 + "subjects", { name: name.value, role: role.value }).then(function () { flash("Owner created."); reload(); }, fail);
      } }, h("h2", { text: "New owner" }), h("div", { class: "row" }, h("div", { class: "field" }, h("label", { text: "Owner name" }), name), h("div", { class: "field" }, h("label", { text: "Role" }), role), h("button", { type: "submit", text: "Create" }))),
      h("div", { class: "card" }, h("h2", { text: "Owners" }), h("p", { class: "muted small", text: "Turning an owner off ends their devices' sessions and streams at once and blocks sign-in until turned back on." }),
        h("table", null, h("thead", null, h("tr", null, ["Name", "Role", "Status", "Created", ""].map(function (t) { return h("th", { text: t }); }))),
          h("tbody", null, cache.subjects.map(function (s) {
            var active = s.status === "active";
            var detail = h("tr", { hidden: true }, h("td", { colspan: "5" }));
            return [h("tr", null, h("td", { text: s.name }), h("td", { text: s.role }),
              h("td", { class: active ? "ok" : "bad", text: s.status }), h("td", { text: when(s.created_at) }),
              h("td", null, h("button", { class: "secondary", text: "Sign-in factors", onclick: function () {
                detail.hidden = !detail.hidden;
                if (!detail.hidden) { clear(detail.firstChild); add(detail.firstChild, ownerFactors(s)); }
              } }), " ", h("button", { class: active ? "danger" : "secondary", text: active ? "Turn off" : "Turn on", onclick: function () {
                if (active && !confirm("Turn off " + s.name + "? All their devices lose access now.")) return;
                api("POST", V2 + "subjects/" + encodeURIComponent(s.id) + (active ? "/disable" : "/enable")).then(reload, fail);
              } }))), detail];
          }))))
    ]);
  };

  // ownerFactors: what an owner can verify with, and a setup link to add more.
  function ownerFactors(s) {
    var path = V2 + "subjects/" + encodeURIComponent(s.id);
    var box = h("div", { class: "detail" }, h("p", { class: "muted", text: "Loading…" }));
    api("GET", path + "/factors").then(function (f) {
      clear(box);
      var rows = h("dl");
      add(rows, h("dt", { text: "Authenticator app" }), h("dd", null, f.totp
        ? ["set up " + when(f.totp.activated_at) + "; " + f.recovery_codes_left + " recovery code(s) left ",
          h("button", { class: "link", text: "remove", onclick: function () {
            if (!confirm("Remove " + s.name + "'s authenticator app and recovery codes? Steps that need a code can't be completed until they set one up again.")) return;
            api("DELETE", path + "/factors/totp").then(function () { clear(box); add(box, ownerFactors(s)); }, fail);
          } })]
        : h("span", { class: "muted", text: "not set up" })));
      add(rows, h("dt", { text: "Passkeys" }), h("dd", null, f.passkeys.length ? h("ul", null, f.passkeys.map(function (k) {
        return h("li", null, k.name + " — added " + when(k.created_at) + (k.last_used_at ? ", last used " + when(k.last_used_at) : "") +
          ", " + (k.backup_eligible ? "synced" : "device-bound") + ", model " + k.attestation.replace("_", " ") +
          (k.clone_warning ? " ⚠ counter warning" : "") + " ",
          h("button", { class: "link", text: "remove", onclick: function () {
            if (!confirm("Remove passkey " + k.name + "?")) return;
            api("DELETE", path + "/factors/passkeys/" + k.index).then(function () { clear(box); add(box, ownerFactors(s)); }, fail);
          } }));
      })) : h("span", { class: "muted", text: "none" })));
      add(box, rows);
      if (s.status !== "active") return;
      var replace = h("input", { type: "checkbox" });
      var out = h("div");
      add(box, h("div", { class: "row" },
        h("button", { text: "Create setup link", onclick: function () {
          api("POST", path + "/setup-link", { replace_totp: replace.checked }).then(function (r) {
            var link = publicOrigin().replace(/\/+$/, "") + r.path;
            clear(out);
            var card = h("div", { class: "card ticket" }, h("div", null,
              h("h3", { text: "Setup link for " + s.name }),
              h("p", { class: "small" }, "Anyone with this link can add sign-in factors for " + s.name + " until " + when(r.expires_at) +
                ". Show the QR code in person or send it privately. Creating another link cancels this one."),
              h("div", { class: "row" }, h("code", { text: link }), copyButton(link))));
            add(out, card);
            drawQR(link).then(function (svg) { add(card, svg); }, fail);
          }, fail);
        } }),
        f.totp ? h("label", { class: "small" }, replace, " let it replace the authenticator app") : null), out);
    }, fail);
    return box;
  }

  // ---- network: Jellyfin, admin networks, applications ----

  tabs.network = function () {
    return api("GET", V2 + "settings").then(function (data) {
      var s = JSON.parse(JSON.stringify(data.settings));
      s.apps = s.apps || [];
      s.admin_allow = s.admin_allow || [];
      var env = data.environment, live = data.effective;

      function input(obj, key, attrs) {
        var el = h("input", Object.assign({ value: obj[key] || "" }, attrs || {}));
        el.addEventListener("input", function () { obj[key] = el.value.trim(); });
        return el;
      }
      function check(obj, key, label, hint) {
        var el = h("input", { type: "checkbox", checked: obj[key] });
        el.addEventListener("change", function () { obj[key] = el.checked; });
        return h("label", { title: hint || "" }, el, " " + label);
      }
      function field(label, el, hint) {
        return h("div", { class: "field" }, h("label", { text: label }), el, hint ? h("span", { class: "muted small", text: hint }) : null);
      }
      function testButton(getURL) {
        var out = h("span", { class: "small" });
        return h("span", null, h("button", { type: "button", class: "secondary", text: "Test", onclick: function () {
          var u = getURL();
          if (!u) { out.textContent = "enter an address"; out.className = "small bad"; return; }
          out.textContent = "…"; out.className = "small muted";
          api("POST", V2 + "settings/test-upstream", { url: u }).then(function (r) {
            out.textContent = r.reachable ? " answered HTTP " + r.status + " in " + r.ms + " ms" + (r.server ? " (" + r.server + ")" : "")
              : " not reachable: " + r.error;
            out.className = "small " + (r.reachable ? "ok" : "bad");
          }, fail);
        } }), out);
      }

      var upstream = input(s, "upstream", { placeholder: env.upstream, size: "34" });
      var primary = input(s, "primary_host", { placeholder: env.primary_host || "flix.example.com", size: "28" });
      var admins = h("textarea", { rows: "4", class: "short", spellcheck: "false", placeholder: env.admin_allow.join("\n") });
      admins.value = s.admin_allow.join("\n");
      admins.addEventListener("input", function () {
        s.admin_allow = admins.value.split(/[\s,]+/).filter(Boolean);
      });
      var tls = data.tls;

      var gateCard = h("div", { class: "card" }, h("h2", { text: "Jellyfin and the Gate" }),
        h("p", { class: "muted small", text: "Empty fields use gate.env. Changes apply to the next request; no restart." }),
        h("div", { class: "row" },
          field("Jellyfin address", upstream, "in use: " + live.upstream),
          testButton(function () { return s.upstream || env.upstream; })),
        h("div", { class: "row" },
          field("Sign-in host (Jellyfin's public name)", primary, live.primary_host ? "in use: " + live.primary_host
            : "not set: applications can't link browsers")),
        h("div", { class: "row" },
          field("Admin networks (one per line: address or CIDR)", admins,
            "in use: " + live.admin_allow.join(", ") + ". Your address " + live.client_address + " must stay in the list.")),
        h("h3", { text: "Set in gate.env (restart to change)" }),
        h("dl", null,
          h("dt", { text: "Internal Jellyfin service" }), h("dd", { class: "mono", text: env.service_listen ? env.service_listen + " on " + env.service_network + "; authentication: " + (env.service_auth || "ip") + "; clients: " + (env.service_clients || []).map(function (c) { return c.name + "=" + c.ip; }).join(", ") : "disabled" }),
          h("dt", { text: "Listening on" }), h("dd", { class: "mono", text: env.listen || "—" }),
          h("dt", { text: "TLS certificate" }), h("dd", null, tls.available
            ? (tls.names || []).join(", ") + " — " + (tls.issuer || "") + ", expires " + when(tls.not_after)
            : h("span", { class: "muted", text: tls.error || "unknown" }))));

      var appBox = h("div");
      function renderApps() {
        clear(appBox);
        if (!s.apps.length) add(appBox, h("p", { class: "muted", text: "No applications yet. Only Jellyfin is behind the Gate." }));
        s.apps.forEach(function (a, i) {
          a.hosts = a.hosts || [];
          a.owners = a.owners || [];
          // Records saved before access modes existed have no access_mode:
          // they keep their original behavior (no owners: every owner) unless
          // the mode is changed here.
          var mode = a.access_mode || (a.owners.length ? "selected" : "everyone");
          var hosts = h("input", { value: a.hosts.join(", "), placeholder: "sonarr.example.com", size: "34" });
          hosts.addEventListener("input", function () { a.hosts = hosts.value.split(/[\s,]+/).filter(Boolean); });
          var modeSel = h("select", null,
            h("option", { value: "everyone", text: "Everyone" }),
            h("option", { value: "selected", text: "Selected owners" }),
            h("option", { value: "admins", text: "Admins only" }));
          modeSel.value = mode;
          modeSel.addEventListener("change", function () { a.access_mode = modeSel.value; renderApps(); });
          var owners = h("span", { class: "days" }, cache.subjects.map(function (o) {
            var c = h("input", { type: "checkbox", checked: a.owners.indexOf(o.id) >= 0 });
            c.addEventListener("change", function () {
              a.access_mode = "selected";
              a.owners = a.owners.filter(function (x) { return x !== o.id; });
              if (c.checked) a.owners.push(o.id);
            });
            return h("label", { title: "Allow " + o.name + " to reach this application when Selected owners is active." }, c, o.name);
          }));
          add(appBox, h("div", { class: "card app" },
            h("div", { class: "row" },
              field("Name", input(a, "name", { placeholder: "Sonarr", maxlength: "64" })),
              check(a, "enabled", "Enabled"),
              h("button", { type: "button", class: "danger", text: "Remove", onclick: function () {
                if (!confirm("Remove " + (a.name || "this application") + "? Its open connections close when you save.")) return;
                s.apps.splice(i, 1); renderApps();
              } })),
            h("div", { class: "row" },
              field("Public hostnames", hosts, "comma-separated; each needs DNS pointing at the Gate and a place in its TLS certificate"),
              field("Address behind the Gate", input(a, "upstream", { placeholder: "http://10.20.0.5:8989", size: "30" })),
              testButton(function () { return a.upstream; })),
            h("div", { class: "row" },
              field("Who can use it", modeSel, mode === "selected" ? "Only the owners ticked below" : null),
              mode === "selected" ? field("Owners allowed (none ticked: no one)", owners) : null),
            h("div", { class: "row" },
              check(a, "preserve_host", "Send the public hostname", "What most apps behind a reverse proxy expect"),
              check(a, "inject_renewal", "Keep browser sessions alive", "Adds the session-renewal script to the app's pages"),
              check(a, "identity_headers", "Send Lanternfish identity headers", "The device ID and a Gate signature, as Jellyfin gets"))));
        });
      }
      renderApps();

      function save() {
        var body = JSON.parse(JSON.stringify(s));
        api("PUT", V2 + "settings", body).then(function (r) {
          flash("Saved (version " + r.version + ").");
          reload();
        }, function (err) {
          if (err.status === 409) flash("The settings were changed meanwhile. Reload to see them.", true);
          else fail(err);
        });
      }

      return [
        data.warnings.length ? h("div", { class: "card" }, data.warnings.map(function (w) { return h("p", { class: "bad", text: "⚠ " + w }); })) : null,
        gateCard,
        h("div", { class: "card" }, h("h2", { text: "Applications behind the Gate" }),
          h("p", { class: "muted small", text: "Each application gets its own hostname. Browsers sign in on the sign-in host and are linked to the application the first time; native apps use their session as usual. Devices, owners and policies are the same as Jellyfin's." }),
          appBox,
          h("button", { type: "button", class: "secondary", text: "Add application", onclick: function () {
            s.apps.push({ name: "", enabled: false, hosts: [], upstream: "", owners: [], access_mode: "selected",
              preserve_host: true, inject_renewal: true, identity_headers: false });
            renderApps();
          } })),
        h("div", { class: "row" }, h("button", { type: "button", text: "Save network settings", onclick: save }),
          s.version ? h("span", { class: "muted small", text: "Version " + s.version + ", saved " + when(s.updated_at) + " by " + s.updated_by }) : null)
      ];
    });
  };

  // ---- firewall: Proxmox rules for the Gate and what's behind it ----

  tabs.firewall = function () {
    return api("GET", V2 + "firewall").then(function (data) {
      var p = JSON.parse(JSON.stringify(data.plan || data.suggested));
      var fresh = !data.plan;
      p.guests = p.guests || [];
      p.gate.ssh_from = p.gate.ssh_from || [];
      var out = h("div"), warnBox = h("div");

      function num(obj, key, attrs) {
        var el = h("input", Object.assign({ type: "number", value: obj[key] || "" }, attrs || {}));
        el.addEventListener("input", function () { obj[key] = Number(el.value) || 0; });
        return el;
      }
      function text(obj, key, attrs) {
        var el = h("input", Object.assign({ value: obj[key] || "" }, attrs || {}));
        el.addEventListener("input", function () { obj[key] = el.value.trim(); });
        return el;
      }
      function list(obj, key, attrs, numbers) {
        var el = h("input", Object.assign({ value: (obj[key] || []).join(", ") }, attrs || {}));
        el.addEventListener("input", function () {
          var v = el.value.split(/[\s,]+/).filter(Boolean);
          obj[key] = numbers ? v.map(Number) : v;
        });
        return el;
      }
      function check(obj, key, label, hint) {
        var el = h("input", { type: "checkbox", checked: obj[key] });
        el.addEventListener("change", function () { obj[key] = el.checked; });
        return h("label", { title: hint || "" }, el, " " + label);
      }
      function field(label, el, hint) {
        return h("div", { class: "field" }, h("label", { text: label }), el, hint ? h("span", { class: "muted small", text: hint }) : null);
      }
      function showWarnings(ws) {
        clear(warnBox);
        (ws || []).forEach(function (w) { add(warnBox, h("p", { class: "bad small", text: "⚠ " + w })); });
      }
      showWarnings(data.warnings);

      var g = p.gate;
      var gateCard = h("div", { class: "card" }, h("h2", { text: "The Gate's container" }),
        h("div", { class: "row" },
          field("Container ID", num(g, "id", { min: 100, placeholder: "200" })),
          field("LAN interface", text(g, "lan_nic", { placeholder: "net0", size: "6" }), "where HTTPS arrives"),
          field("Internal address", text(g, "internal_ip", { placeholder: "10.20.0.2", size: "14" }), "the Gate's IP on the internal network"),
          field("Public HTTPS port", num(g, "public_port", { min: 1, max: 65535 }))),
        h("div", { class: "row" },
          field("Internal service port", num(g, "service_port", { min: 0, max: 65535, placeholder: "0" }), "0 disables; match LANTERNFISH_SERVICE_LISTEN"),
          field("Internal interface", text(g, "internal_nic", { placeholder: "net1", size: "6" }), "separate from the LAN interface")),
        h("p", { class: "muted small", text: "Internal Jellyfin service access also requires named clients and an isolated subnet in gate.env. It never opens a public sign-in bypass." }),
        h("div", { class: "row" },
          field("Internal network", text(p, "internal_net", { placeholder: "10.20.0.0/24", size: "16" })),
          field("SSH allowed from", list(g, "ssh_from", { placeholder: "192.168.1.10", size: "30" }), "addresses or networks; empty: no SSH"),
          check(g, "allow_ping", "Answer ping")));

      var isolationCard = h("div", { class: "card" }, h("h2", { text: "Optional LAN isolation" }),
        h("p", { class: "muted small", text: "These blocks apply to guests with Keep it off my LAN enabled. Explicit guest, internal service and external target allowances take precedence." }),
        field("Additional LAN networks", list(p, "blocked_networks", { placeholder: "2001:db8:1234::/48", size: "40" }), "CIDR prefixes, including any public IPv6 ranges on your LAN; empty keeps the existing private-range blocks"),
        check(p, "block_link_local", "Also block link-local and multicast destinations", "Includes metadata/link-local addresses and discovery multicast; enable only if your apps do not need them"));

      var guestBox = h("div");
      function renderGuests() {
        clear(guestBox);
        if (!p.guests.length) add(guestBox, h("p", { class: "muted", text: "No guests yet." }));
        p.guests.forEach(function (x, i) {
          x.talks_to = x.talks_to || [];
          x.sources = x.sources || [];
          x.egress = x.egress || [];
          var kind = h("select", null, h("option", { value: "ct", text: "container (CT)" }), h("option", { value: "vm", text: "virtual machine" }));
          kind.value = x.kind || "ct";
          kind.addEventListener("change", function () { x.kind = kind.value; });
          var name = text(x, "name", { placeholder: "Sonarr", maxlength: "40", size: "14" });
          var prevName = x.name;
          name.addEventListener("change", function () { // keep "talks to" pointing at the renamed guest
            p.guests.forEach(function (y) {
              y.talks_to = (y.talks_to || []).map(function (n) { return n === prevName ? x.name : n; });
            });
            setTimeout(renderGuests, 0); // not while the browser is still moving focus out of this field
          });
          var talks = h("span", { class: "days" }, p.guests.filter(function (y) { return y !== x && y.name; }).map(function (y) {
            var c = h("input", { type: "checkbox", checked: x.talks_to.indexOf(y.name) >= 0 });
            c.addEventListener("change", function () {
              x.talks_to = x.talks_to.filter(function (n) { return n !== y.name; });
              if (c.checked) x.talks_to.push(y.name);
            });
            return h("label", { title: "Allow this guest to connect to " + y.name + " on its listed ports. Reverse access requires its own rule." }, c, y.name);
          }));
          // External targets: a NAS, for example. Outbound only, one literal
          // address each, with an explicit protocol and ports.
          var egressBox = h("div");
          function renderEgress() {
            clear(egressBox);
            x.egress.forEach(function (t, ti) {
              var ipEl = h("input", { value: t.ip || "", placeholder: "192.168.1.50", size: "14" });
              ipEl.addEventListener("input", function () { t.ip = ipEl.value.trim(); });
              var proto = h("select", null, h("option", { value: "tcp", text: "TCP" }), h("option", { value: "udp", text: "UDP" }));
              proto.value = t.protocol || "tcp";
              proto.addEventListener("change", function () { t.protocol = proto.value; });
              var portsEl = h("input", { value: (t.ports || []).join(", "), placeholder: "445", size: "12" });
              portsEl.addEventListener("input", function () {
                t.ports = portsEl.value.split(/[\s,]+/).filter(Boolean).map(Number);
              });
              add(egressBox, h("div", { class: "row" },
                field("Target address", ipEl),
                field("Protocol", proto),
                field("Ports", portsEl),
                h("button", { type: "button", class: "danger", text: "Remove", onclick: function () {
                  x.egress.splice(ti, 1);
                  renderEgress();
                } })));
            });
            if (!x.egress.length) add(egressBox, h("span", { class: "muted small", text: "none" }));
          }
          renderEgress();
          add(guestBox, h("div", { class: "card app" },
            h("div", { class: "row" }, field("Name", name), field("Type", kind),
              field("ID", num(x, "id", { min: 100, placeholder: "203" })),
              field("Address", text(x, "ip", { placeholder: "10.20.0.5", size: "14" })),
              field("Ports", list(x, "ports", { placeholder: "8989", size: "12" }, true)),
              field("Interface", text(x, "nic", { placeholder: "net0", size: "6" })),
              h("button", { type: "button", class: "danger", text: "Remove", onclick: function () {
                var gone = x.name;
                p.guests.splice(i, 1);
                p.guests.forEach(function (y) { y.talks_to = (y.talks_to || []).filter(function (n) { return n !== gone; }); });
                renderGuests();
              } })),
            h("div", { class: "row" },
              check(x, "from_gate", "The Gate reaches it", "Jellyfin and applications behind the Gate"),
              check(x, "to_service", "Internal Jellyfin service access", "Only for named backends such as Seerr, also authorized in gate.env"),
              check(x, "block_private", "Keep it off my LAN", "It can reach the internet, but private networks need an explicit guest, service or external target rule"),
              field("Talks to", talks.childNodes.length ? talks : h("span", { class: "muted small", text: "no other guests" }), "one-way access to their ports; add a separate tick for reverse access"),
              field("Also allow from", list(x, "sources", { placeholder: "none", size: "20" }), "optional addresses or networks")),
            h("div", { class: "row" },
              h("span", { class: "muted small", text: "External targets (outbound to one address each):" }),
              h("button", { type: "button", class: "secondary", text: "Add external target", onclick: function () {
                x.egress.push({ ip: "", protocol: "tcp", ports: [] });
                renderEgress();
              } })),
            egressBox,
            h("p", { class: "muted small", text: "Reached directly and outbound only: one literal address, one protocol, up to 16 ports, kept reachable even with \"Keep it off my LAN\" on. Your NAS is SMB TCP 445 or NFSv4 TCP 2049 — NFSv3 needs its own fixed ports." })));
        });
      }
      renderGuests();

      function fillFromNetwork() {
        var have = {};
        p.guests.forEach(function (x) { have[x.ip] = true; });
        var added = 0;
        (data.suggested.guests || []).forEach(function (x) {
          if (!have[x.ip]) { p.guests.push(JSON.parse(JSON.stringify(x))); added++; }
        });
        renderGuests();
        flash(added ? "Added " + added + " guest(s) from the Network tab; fill in their IDs." : "Every address from the Network tab is already here.");
      }

      function save() {
        return api("PUT", V2 + "firewall", p).then(function (r) {
          p.version = r.version;
          showWarnings(r.warnings);
          flash("Firewall plan saved (version " + r.version + ").");
        }, function (err) {
          if (err.status === 409) flash("The plan was changed meanwhile. Reload to see it.", true);
          else fail(err);
        });
      }
      function generate() {
        api("POST", V2 + "firewall/script", p).then(function (r) {
          showWarnings(r.warnings);
          clear(out);
          var url = URL.createObjectURL(new Blob([r.script], { type: "text/x-shellscript" }));
          add(out, h("div", { class: "card" }, h("h2", { text: "Script for the Proxmox host" }),
            h("p", { class: "small" }, "Copy it to the Proxmox host (not the Gate) and run it as root. Try ",
              h("code", { text: "DRY_RUN=1 bash " + r.filename }), " first: it shows the files and changes nothing."),
            h("div", { class: "row" }, h("a", { class: "button", href: url, download: r.filename, text: "Download " + r.filename }),
              copyButton(r.script)),
            h("pre", { class: "script", text: r.script })));
        }, fail);
      }

      return [
        h("div", { class: "card" }, h("h2", { text: "Proxmox firewall" }),
          h("p", { class: "muted small", text: "Describe the Gate's container and every container or VM behind it, then generate a script for the Proxmox host. It writes each guest's firewall so only the Gate (and the guests you choose) can reach it, and a guest can't pretend to be the Gate. Give guests static addresses." }),
          h("p", { class: "muted small", text: "Keep each application's own login on: leave authentication set to Forms, never \"Disabled for Local Addresses\". The Gate decides who may reach an app, not who they are inside it." }),
          fresh ? h("p", { class: "small", text: "Started from the Network tab's addresses. Fill in the container IDs and save." }) : null,
          warnBox),
        gateCard,
        isolationCard,
        h("div", { class: "card" }, h("h2", { text: "Behind the Gate" }), guestBox,
          h("div", { class: "row" },
            h("button", { type: "button", class: "secondary", text: "Add guest", onclick: function () {
              p.guests.push({ name: "", kind: "ct", id: 0, ip: "", ports: [], from_gate: true, talks_to: [], sources: [], egress: [], block_private: true, nic: "net0" });
              renderGuests();
            } }),
            h("button", { type: "button", class: "secondary", text: "Add from Network settings", onclick: fillFromNetwork }))),
        h("div", { class: "row" }, h("button", { type: "button", text: "Save plan", onclick: save }),
          h("button", { type: "button", class: "secondary", text: "Generate script", onclick: generate }),
          p.version ? h("span", { class: "muted small", text: "Version " + p.version + ", saved " + when(p.updated_at) + " by " + p.updated_by }) : null),
        out
      ];
    });
  };

  // ---- security: deployment status, admin keys ----

  tabs.security = function () {
    return Promise.all([api("GET", V2 + "status"), api("GET", V2 + "admin-keys")]).then(function (r) {
      var st = r[0], keys = r[1];
      var wa = st.webauthn, geo = st.geoip;
      var me = keys.admin_keys.filter(function (k) { return k.current; })[0];
      var admins = cache.subjects.filter(function (s) { return s.role === "admin" && s.status === "active"; });
      var link = h("select", null, h("option", { value: "", text: "not linked" }),
        admins.map(function (s) { return h("option", { value: s.id, text: s.name }); }));
      link.value = me ? me.subject_id || "" : "";
      return [
        h("div", { class: "card" }, h("h2", { text: "This Gate" }), h("dl", null,
          h("dt", { text: "Passkeys" }), h("dd", { class: wa.configured ? "ok" : "muted", text: wa.configured
            ? "on for " + wa.rp_id + " (" + wa.origins.join(", ") + ")" + (wa.trusted_attestation_available ? "; FIDO metadata loaded" : "; no FIDO metadata (\"only certified models\" unavailable)") +
              (wa.metadata_error ? " — metadata error: " + wa.metadata_error : "")
            : "off — set LANTERNFISH_WEBAUTHN_RP_ID and LANTERNFISH_WEBAUTHN_ORIGINS" }),
          h("dt", { text: "Country database" }), h("dd", { class: !geo.configured ? "muted" : (geo.error || geo.stale ? "bad" : "ok"), text: !geo.configured
            ? "off — set LANTERNFISH_GEOIP_DB to a GeoLite2-Country.mmdb file"
            : (geo.error ? "error: " + geo.error : "built " + when(geo.built) + " (" + geo.age_days + " days old" + (geo.stale ? ", STALE: lookups return unknown" : "") + ")") }),
          h("dt", { text: "Your address" }), h("dd", { class: "mono", text: st.client_address }),
          h("dt", { text: "Server time" }), h("dd", { text: when(st.server_time) }))),
        h("div", { class: "card" }, h("h2", { text: "Your admin key" }),
          h("p", { class: "muted small", text: "Link this key to an admin owner with an authenticator app, and changes to policy, owners' factors and updates need a code from that app (asked at most every 5 minutes)." }),
          h("div", { class: "row" }, h("div", { class: "field" }, h("label", { text: "Linked owner" }), link),
            h("button", { text: "Save", onclick: function () {
              api("POST", UI + "link", { subject_id: link.value }).then(function () { flash("Saved."); reload(); }, fail);
            } })),
          keys.you_have_factor ? h("p", { class: "ok small", text: "Re-verification is on for this key." }) :
            h("p", { class: "muted small", text: "Re-verification is off for this key." })),
        h("div", { class: "card" }, h("h2", { text: "Admin keys" }),
          h("p", { class: "muted small", text: "Create and revoke keys on the Gate host: lanternfish-gate admin-key create -name NAME -scopes tickets,devices" }),
          h("table", null, h("thead", null, h("tr", null, ["Name", "Created", "Scopes", "Linked owner", ""].map(function (t) { return h("th", { text: t }); }))),
            h("tbody", null, keys.admin_keys.map(function (k) {
              return h("tr", null, h("td", { text: k.name + (k.current ? " (you)" : "") }), h("td", { text: when(k.created_at) }),
                h("td", { class: "small", text: k.legacy_all_scopes ? "all" : k.scopes.join(", ") }),
                h("td", { text: k.subject_id ? subjectName(k.subject_id) : "—" }),
                h("td", { class: k.revoked ? "bad" : "", text: k.revoked ? "revoked" : "" }));
            }))))
      ];
    });
  };

  // ---- audit ----

  tabs.audit = function () {
    var q = h("input", { type: "search", placeholder: "filter, e.g. revoked or dev_…" });
    var box = h("div");
    function load() {
      api("GET", UI + "v2/audit?limit=300&q=" + encodeURIComponent(q.value)).then(function (d) {
        clear(box);
        if (d.note) add(box, h("p", { class: "muted", text: d.note }));
        if (!d.entries.length) { add(box, h("p", { class: "muted", text: "No entries." })); return; }
        add(box, h("table", null, h("thead", null, h("tr", null, ["Time", "Event", "Details"].map(function (t) { return h("th", { text: t }); }))),
          h("tbody", null, d.entries.map(function (e) {
            var rest = {};
            Object.keys(e).forEach(function (k) { if (k !== "time" && k !== "event") rest[k] = e[k]; });
            var bad = /fail|denied|revoke/.test(e.event);
            return h("tr", null, h("td", { text: when(e.time) }), h("td", { class: bad ? "bad" : "", text: e.event }),
              h("td", { class: "mono small", text: JSON.stringify(rest) }));
          }))));
      }, fail);
    }
    q.addEventListener("change", load);
    load();
    return Promise.resolve(h("div", { class: "card" }, h("div", { class: "row" }, h("h2", { text: "Audit log" }), h("div", { class: "field" }, h("label", { text: "Audit filter" }), q),
      h("button", { class: "secondary", text: "Refresh", onclick: load })), box));
  };

  // ---- updates ----

  var pollTimer = null;
  tabs.updates = function () {
    clearTimeout(pollTimer);
    return api("GET", V2 + "update").then(function (u) {
      var out = [];
      var head = h("div", { class: "card" }, h("h2", { text: "Updates" }),
        h("p", null, "Running ", h("strong", { text: u.current }), "."));
      out.push(head);
      if (!u.supported) {
        add(head, h("p", { class: "bad", text: "Updating from here isn't available: " + (u.reason || "unknown reason") }),
          h("p", { class: "muted small", text: "See docs/RELEASES.md. The updater comes with install-gate.sh from release 0.2.1 or later; official builds carry the release signing key." }));
      }
      if (u.status) {
        var s = u.status, cls = s.state === "succeeded" ? "ok" : (s.state === "installing" ? "" : "bad");
        add(head, h("p", null, "Last update: ", h("strong", { class: cls, text: s.state.replace(/_/g, " ") }),
          " " + s.version + " (from " + s.from + ")" + (s.requested_by ? " by " + s.requested_by : "") + ", " + when(s.at) + ". ",
          h("span", { class: "muted", text: s.message })));
      }
      if (u.pending || (u.status && u.status.state === "installing")) {
        add(head, h("p", { text: "An update is in progress. The Gate restarts during it (about 30 seconds; playing streams drop), and you'll need to sign in again." }));
        pollTimer = setTimeout(function () { if (location.hash === "#updates") reload(); }, 4000);
      }
      if (u.error) add(head, h("p", { class: "bad", text: "Couldn't check GitHub: " + u.error }));
      if (u.latest) {
        add(head, h("p", null, "Newest verified release: ", h("strong", { text: u.latest.version }),
          ", signed by " + u.latest.signed_by + ", published " + when(u.latest.published_at) + ". ",
          h("a", { href: safeURL(u.latest.url), target: "_blank", rel: "noopener noreferrer", text: "Release notes" })));
        if (u.update_available && u.supported && !u.pending) {
          add(head, h("button", { text: "Install " + u.latest.version, onclick: function (e) {
            if (!confirm("Install " + u.latest.version + "? The Gate restarts (about 30 seconds); playing streams drop and everyone's browser renews its session. If the new version isn't healthy it is rolled back automatically.")) return;
            e.target.disabled = true;
            api("POST", V2 + "update", { version: u.latest.version }).then(function () {
              flash("Update to " + u.latest.version + " requested.");
              reload();
            }, function (err) { e.target.disabled = false; fail(err); });
          } }));
        } else if (!u.update_available) {
          add(head, h("p", { class: "ok", text: "Up to date." }));
        }
      } else if (u.supported && !u.error) {
        add(head, h("p", { class: "muted", text: "No signed release found yet." }));
      }
      add(head, h("div", { class: "row" },
        h("button", { class: "secondary", text: "Check now", onclick: function () {
          api("GET", V2 + "update?refresh=1").then(reload, fail);
        } }),
        h("span", { class: "muted small", text: u.checked_at ? "Checked " + when(u.checked_at) + "." : "" })));
      if (u.auto_update !== undefined) {
        add(head, h("p", { class: "muted small", text: "Automatic updates: " + u.auto_update +
          (u.auto_update === "off" ? "" : " (installed nightly)") + ". Set LANTERNFISH_AUTO_UPDATE in /etc/lanternfish/gate.env to off, patch, minor or all." }));
      }
      if (u.candidates && u.candidates.length) {
        out.push(h("div", { class: "card" }, h("h2", { text: "Recent releases" }), h("table", null,
          h("thead", null, h("tr", null, ["Release", "Published", "Signature"].map(function (t) { return h("th", { text: t }); }))),
          h("tbody", null, u.candidates.map(function (c) {
            return h("tr", null, h("td", null, h("a", { href: safeURL(c.url), target: "_blank", rel: "noopener noreferrer", text: c.tag }),
              c.prerelease ? " (pre-release)" : ""), h("td", { text: when(c.published_at) }),
              h("td", { class: c.verified ? "ok" : "bad", text: c.verified ? "verified, " + c.signed_by : c.problem }));
          })))));
      }
      return out;
    }, function (err) {
      // The Gate restarting mid-update: keep trying.
      if (err && err.message === "signed out") throw err;
      pollTimer = setTimeout(function () { if (location.hash === "#updates") reload(); }, 4000);
      return h("div", { class: "card" }, h("p", { text: "Waiting for the Gate… (" + err.message + ")" }));
    });
  };

  // ---- start ----

  api("GET", UI + "session").then(signedIn, function () { showSignIn(""); });
})();
