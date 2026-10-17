(function () {
 "use strict";
 var token = new URLSearchParams(location.hash.slice(1)).get("token");
 history.replaceState(null, "", "/_lanternfish/claim/");
 var button = document.getElementById("accept"), status = document.getElementById("status");
 if (!token) { button.hidden = true; status.textContent = "Open the invitation link from your email."; }
 // A user action avoids consuming invitations during automated email-link scans.
 button.onclick = async function () {
  button.disabled = true;
  try {
   var res = await fetch("/_lanternfish/v2/claim", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ token: token }) });
   var data = await res.json();
   if (!res.ok) throw new Error(data.error || "Invitation unavailable");
   token = null;
   location.replace("/_lanternfish/#ticket=" + encodeURIComponent(data.ticket));
  } catch (e) { status.textContent = e.message; button.disabled = false; }
 };
})();
