// Lanternfish Gate admin dashboard. Plain DOM, no third-party code: every
// value from the Gate is inserted as text, never as HTML.
(function () {
  "use strict";

  var csrf = "";
  var view = document.getElementById("view");
  var flashEl = document.getElementById("flash");
  var DAYS = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"];
  var PLATFORMS = ["web", "android", "firetv", "webos", "tizen", "roku"];

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

  function api(method, path, body) {
    var opts = { method: method, credentials: "same-origin", headers: {} };
    if (method !== "GET") opts.headers["X-Lanternfish-CSRF"] = csrf;
    if (body !== undefined) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(body);
    }
    return fetch(path, opts).then(function (res) {
      if (res.status === 204) return {};
      return res.json().catch(function () { return {}; }).then(function (data) {
        if (res.status === 401 && path.indexOf("/session") < 0) {
          showSignIn("Your admin session ended. Sign in again.");
          throw new Error("signed out");
        }
        if (!res.ok) {
          var err = new Error(data.error || ("HTTP " + res.status));
          err.status = res.status;
          err.data = data;
          throw err;
        }
        return data;
      });
    });
  }
  var V1 = "/_lanternfish/admin/v1/", V2 = "/_lanternfish/admin/v2/", UI = "/_lanternfish/admin/";

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
    loadLookups().then(function () { return tabs[tab](); }).then(function (content) {
      clear(view);
      add(view, content);
    }).catch(fail);
  }
  Array.prototype.forEach.call(document.querySelectorAll("nav button"), function (b) {
    b.addEventListener("click", function () { flash(""); go(b.dataset.tab); });
  });
  function reload() { go(location.hash.slice(1)); }

  // ---- devices ----

  tabs.devices = function () {
    return api("GET", V1 + "devices").then(function (data) {
      var showRevoked = h("input", { type: "checkbox", id: "showrev" });
      var table = h("table", null, h("thead", null, h("tr", null,
        ["Device", "Owner", "Policy", "Networks", "Sessions", "Last sign-in", ""].map(function (t) { return h("th", { text: t }); }))));
      var body = h("tbody");
      add(table, body);
      function render() {
        clear(body);
        data.devices.filter(function (d) { return showRevoked.checked || !d.revoked_at; }).forEach(function (d) {
          var prof = profileSelect(d.profile_id);
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
          add(body, h("tr", null,
            h("td", null, h("strong", { text: d.name || "(unnamed)" }), h("div", { class: "muted small" },
              d.platform + " · ", h("span", { class: "mono", text: d.id }), " · enrolled " + when(d.created_at) + " from " + d.enrolled_from)),
            h("td", { text: subjectName(d.subject_id) }),
            h("td", null, prof, h("div", { class: "muted small", text: "v" + d.policy_version })),
            h("td", null, nets),
            h("td", { text: String(d.live_sessions || 0) }),
            h("td", { text: when(d.last_auth_at) }),
            h("td", null, status)));
        });
        if (!body.firstChild) add(body, h("tr", null, h("td", { colspan: "7", class: "muted", text: "No devices yet. Create a ticket to enroll one." })));
      }
      showRevoked.addEventListener("change", render);
      render();
      return h("div", { class: "card" }, h("div", { class: "row" }, h("h2", { text: "Devices" }),
        h("label", { class: "small" }, showRevoked, " show revoked")), table);
    });
  };

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
          return h("label", null, c, d);
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
        field("New network", pick(ip, "on_change", [["key_proof", "allow after a fresh device-key signature"], ["deny", "deny (re-enroll to add networks)"]])),
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
    add(root, h("h3", { text: "Preview" }), week);
    renderWindows();
    renderBlackouts();
    renderSchedule();
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
      var reason = h("input", { placeholder: "why (recorded in the history)", size: "40", maxlength: "64" });
      var current = null;

      function scope() { return scopes.filter(function (s) { return s.id === scopeSel.value; })[0]; }
      function load(policy) {
        clear(holder); clear(previewBox);
        form = policyForm(policy);
        json.value = JSON.stringify(policy, null, 2);
        add(holder, jsonMode.checked ? json : form.el);
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
        add(holder, jsonMode.checked ? json : form.el);
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
        h("div", { class: "row" }, h("h2", { text: "Access policy" }), scopeSel,
          h("button", { type: "button", class: "secondary", text: "Load recommended", onclick: function () {
            api("GET", V2 + "policy/recommended").then(function (r) { load(r.policy); flash("Recommended policy loaded; review and publish."); }, fail);
          } }),
          h("label", { class: "small" }, jsonMode, " edit as JSON")),
        meta, holder,
        h("div", { class: "row" }, h("button", { type: "button", class: "secondary", text: "Preview", onclick: preview }),
          reason, h("button", { type: "button", text: "Publish", onclick: publish })),
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
      } }, h("h2", { text: "New profile" }), h("div", { class: "row" }, name, h("button", { type: "submit", text: "Create" }))),
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
      } }, h("h2", { text: "New owner" }), h("div", { class: "row" }, name, role, h("button", { type: "submit", text: "Create" }))),
      h("div", { class: "card" }, h("h2", { text: "Owners" }), h("p", { class: "muted small", text: "Turning an owner off ends their devices' sessions and streams at once and blocks sign-in until turned back on." }),
        h("table", null, h("thead", null, h("tr", null, ["Name", "Role", "Status", "Created", ""].map(function (t) { return h("th", { text: t }); }))),
          h("tbody", null, cache.subjects.map(function (s) {
            var active = s.status === "active";
            return h("tr", null, h("td", { text: s.name }), h("td", { text: s.role }),
              h("td", { class: active ? "ok" : "bad", text: s.status }), h("td", { text: when(s.created_at) }),
              h("td", null, h("button", { class: active ? "danger" : "secondary", text: active ? "Turn off" : "Turn on", onclick: function () {
                if (active && !confirm("Turn off " + s.name + "? All their devices lose access now.")) return;
                api("POST", V2 + "subjects/" + encodeURIComponent(s.id) + (active ? "/disable" : "/enable")).then(reload, fail);
              } })));
          }))))
    ]);
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
    return Promise.resolve(h("div", { class: "card" }, h("div", { class: "row" }, h("h2", { text: "Audit log" }), q,
      h("button", { class: "secondary", text: "Refresh", onclick: load })), box));
  };

  // ---- start ----

  api("GET", UI + "session").then(signedIn, function () { showSignIn(""); });
})();
