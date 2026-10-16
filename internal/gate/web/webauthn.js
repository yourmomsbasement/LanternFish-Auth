// WebAuthn helpers: convert the Gate's JSON options to what
// navigator.credentials expects, and credentials back to JSON. The Gate's
// library does all verification; this only moves bytes.
(function () {
  "use strict";

  function toBuf(s) {
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    var bin = atob(s), out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  }
  function fromBuf(buf) {
    var bytes = new Uint8Array(buf), s = "";
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function supported() {
    return !!(window.PublicKeyCredential && navigator.credentials && window.isSecureContext);
  }

  function create(options) {
    var pk = options.publicKey;
    pk.challenge = toBuf(pk.challenge);
    pk.user.id = toBuf(pk.user.id);
    (pk.excludeCredentials || []).forEach(function (c) { c.id = toBuf(c.id); });
    return navigator.credentials.create({ publicKey: pk }).then(function (cred) {
      var r = cred.response;
      return {
        id: cred.id, rawId: fromBuf(cred.rawId), type: cred.type,
        authenticatorAttachment: cred.authenticatorAttachment || undefined,
        clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
        response: {
          clientDataJSON: fromBuf(r.clientDataJSON),
          attestationObject: fromBuf(r.attestationObject),
          transports: r.getTransports ? r.getTransports() : undefined
        }
      };
    });
  }

  function get(options) {
    var pk = options.publicKey;
    pk.challenge = toBuf(pk.challenge);
    (pk.allowCredentials || []).forEach(function (c) { c.id = toBuf(c.id); });
    return navigator.credentials.get({ publicKey: pk }).then(function (cred) {
      var r = cred.response;
      return {
        id: cred.id, rawId: fromBuf(cred.rawId), type: cred.type,
        authenticatorAttachment: cred.authenticatorAttachment || undefined,
        clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
        response: {
          clientDataJSON: fromBuf(r.clientDataJSON),
          authenticatorData: fromBuf(r.authenticatorData),
          signature: fromBuf(r.signature),
          userHandle: r.userHandle ? fromBuf(r.userHandle) : undefined
        }
      };
    });
  }

  // call POSTs JSON to a Gate endpoint and returns the parsed reply,
  // rejecting with err.status/err.data on failure.
  function call(path, body, headers) {
    var h = { "Content-Type": "application/json" };
    Object.keys(headers || {}).forEach(function (k) { h[k] = headers[k]; });
    return fetch(path, { method: body === undefined ? "GET" : "POST", credentials: "same-origin", headers: h,
      body: body === undefined ? undefined : JSON.stringify(body) }).then(function (res) {
      if (res.status === 204) return {};
      return res.json().catch(function () { return {}; }).then(function (data) {
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

  // qrSVG draws QR rows ("0101…") as an SVG element.
  function qrSVG(rows, label) {
    var ns = "http://www.w3.org/2000/svg", n = rows.length + 8;
    var svg = document.createElementNS(ns, "svg");
    svg.setAttribute("viewBox", "0 0 " + n + " " + n);
    svg.setAttribute("class", "qr");
    svg.setAttribute("role", "img");
    svg.setAttribute("aria-label", label || "QR code");
    svg.setAttribute("shape-rendering", "crispEdges");
    var bg = document.createElementNS(ns, "rect");
    bg.setAttribute("width", n); bg.setAttribute("height", n); bg.setAttribute("fill", "#fff");
    svg.appendChild(bg);
    var d = "";
    rows.forEach(function (row, y) {
      for (var x = 0; x < row.length; x++) if (row.charAt(x) === "1") d += "M" + (x + 4) + " " + (y + 4) + "h1v1h-1z";
    });
    var path = document.createElementNS(ns, "path");
    path.setAttribute("d", d);
    path.setAttribute("fill", "#000");
    svg.appendChild(path);
    return svg;
  }

  window.LanternfishWebAuthn = { supported: supported, create: create, get: get, call: call, qrSVG: qrSVG };
})();
