(function(){
 "use strict";
 var status=document.getElementById("status"),form=document.getElementById("account"),button=form.querySelector("button"),next="/";
 try{var u=new URL(new URLSearchParams(location.search).get("next")||"/",location.origin);if(u.origin===location.origin)next=u.pathname+u.search+u.hash;}catch(e){}
 document.getElementById("continue").href=next;
 window.LanternfishGate.signIn().then(function(){return fetch("/_lanternfish/v2/jellyfin/account",{credentials:"same-origin"});}).then(function(r){if(!r.ok)throw new Error("Sign in with your enrolled device first.");return r.json();}).then(function(d){
  form.hidden=!d.available || !!d.state;status.textContent=d.created?"Your Jellyfin account has already been created.":d.state?"Account setup requires administrator review.":d.available?"Choose your login. Your administrator has already selected your libraries and permissions.":"This enrollment does not include Jellyfin account creation.";
 },function(e){status.textContent=e.message;});
 form.onsubmit=function(e){e.preventDefault();var password=document.getElementById("password"),confirm=document.getElementById("confirm");if(password.value!==confirm.value){status.textContent="Passwords do not match.";return;}button.disabled=true;
 fetch("/_lanternfish/v2/jellyfin/account",{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-Lanternfish-Account":"create"},body:JSON.stringify({username:document.getElementById("username").value,password:password.value})}).then(function(r){return r.json().then(function(d){if(!r.ok)throw new Error(d.error||"Account creation failed");return d;});}).then(function(){password.value="";confirm.value="";form.hidden=true;status.textContent="Your Jellyfin account is ready. Continue and sign in with your new username and password.";},function(e){password.value="";confirm.value="";status.textContent=e.message;button.disabled=false;});
 };
})();
