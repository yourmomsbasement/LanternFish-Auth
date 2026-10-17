# Email invitations and optional Jellyfin accounts

Open **Email** in the administrator dashboard. Email delivery is infrastructure,
separate from applications routed through the Gate.

## Configure the relay

Enable email, enter the actual Postfix LXC LAN address, port `25`, sender name
`LanternFish Enrollment`, and sender address
`enrollment.lanternfish@cindertrace.com`. Enter the public HTTPS origin used for
browser enrollment, for example `https://media.example.com`. Save, then send a
test email. There is deliberately no assumed Postfix address.

Leave STARTTLS off only for the restricted internal hop. When enabled it is
required, uses certificate verification, and never falls back to plaintext.
LanternFish does not accept SMTP or Brevo credentials. Postfix owns authentication,
mandatory STARTTLS to Brevo on port 587, durable delivery, and retries. Restrict
Postfix's `mynetworks` and firewall to the Gate (`192.168.1.135/32` in this
deployment). Never forward Postfix SMTP ports from the Internet.

A `202` response means queued locally, not delivered to the mailbox. Refresh the
Email tab to see `sent` (accepted by Postfix) or `email_failed`. Test submission
results appear in Audit log. SMTP connections have a ten-second total deadline.
At most 16 jobs run at once. The Gate's queue is intentionally in memory; Postfix
provides durable queueing after acceptance. Graceful shutdown waits for jobs.
A process crash may leave a queued status with an unknown submission outcome;
retry rotates the claim and invalidates the previous link.

## Issue an invitation

Use **Send enrollment invitation** in Email, choose recipient, platform, owner,
policy profile, label and expiry (default 15 minutes, maximum 60). Copy Link is
available in the immediate creation response only. The recipient is used for mail
submission and is not retained in the claim or audit trail. A failed submission
leaves the claim usable. Use the copied link, **Retry email**, or **Revoke**.
Retry needs a recipient again because recipient addresses are not stored; it
revokes the previous claim, preserves the policy and original expiry, and returns
a fresh link. Invitations with less than a minute remaining must be recreated.

Claims use 256 random bits, an `lfc_` prefix and SHA-256 storage. The URL fragment
is removed immediately on the landing page. The recipient clicks Accept to avoid
consumption by ordinary mail scanners. A transactional exchange consumes the
claim exactly once and creates a normal `lft_` ticket with the same expiry.
Device key proof and the owner's configured enrollment factors still apply.
Copying or forwarding an unused link transfers its enrollment authority.

Limits: 20 invitations per hour per admin and source IP, 3 per recipient, 5 test
emails per admin. These conservative defaults are process-local and reset on
restart. Recipients in rate-limit memory are keyed by a hash; no addresses or
bearer credentials enter audit metadata. Admin endpoints inherit existing network,
scoped-key, session and CSRF protections. Settings use the `settings` scope;
invitations use `tickets`.

## Optional Jellyfin account

In Email, configure the internal Jellyfin server URL and an administrator API key
under **Jellyfin account provisioning**. The API key is sealed with the Gate's
master key, never returned to the browser, and sent only in an HTTP header.
Use HTTPS when the internal network is not trusted. Redirects are refused.
The Gate signs these API requests with its existing upstream signing key, so
the LanternFish Jellyfin plugin can stay enforced. Keep using Jellyfin's direct
internal URL, not the public Gate URL. Both the Gate signature and the Jellyfin
API key are required when the plugin is enforced.

Both **Tickets → New enrollment ticket** and emailed invitations include
**Optional Jellyfin account**. Enable it, load libraries, select at least one,
and choose playback, remote access, downloads and transcoding/remuxing. This
policy is copied into the ticket, then into the enrolled device. It cannot be
selected or expanded by the recipient. Existing tickets without this option
continue to enroll normally. Only the explicitly selected libraries are enabled;
new libraries are not automatically granted. Accounts never receive admin,
content deletion, live TV, public sharing or control of other users.

After enrollment and any required owner verification, browser recipients are
prompted to choose a username and a password of at least 12 characters at
`/_lanternfish/account/`. Native users must access this page with the enrolled
device's authorized session/certificate; a separate un-enrolled browser does not
inherit the invitation. Credentials are submitted to Jellyfin, never stored by
LanternFish and never emailed. This creates a Jellyfin account; users still sign
into Jellyfin normally. The Gate device key remains independent of that login.

Provisioning is single-use per enrolled device. It creates the Jellyfin user with
an unguessable temporary password, applies a disabled restricted policy, sets the
chosen password, then enables the account. On a confirmed downstream failure,
it attempts to delete the newly created account. An ambiguous failure or crash
locks setup as `creating` / `needs_admin_review` to prevent automatic duplicate
creation. Administrators must inspect Jellyfin and the device record before
reissuing enrollment; failures are audited using device IDs, never credentials.
Do not enable this option repeatedly for the same person unless separate
Jellyfin accounts are intended.

The Jellyfin calls follow its [User API](https://typescript-sdk.jellyfin.org/functions/generated-client.UserApiAxiosParamCreator.html)
and [UserPolicy schema](https://typescript-sdk.jellyfin.org/interfaces/generated-client.UserPolicy.html).
Test against the deployed Jellyfin version before production use.

## API summary

- `GET/PUT /_lanternfish/admin/v2/email`: relay and public-origin settings.
- `POST .../email/test`: `{ "recipient": "user@example.com" }`.
- `GET/POST .../email/invitations`: status / creation. Creation accepts
  `recipient`, `platform`, `label`, `ttl_seconds`, `subject_id`, `profile_id`,
  and optional `jellyfin_enrollment`.
- `POST .../email/invitations/{id}/retry`: recipient; rotates/revokes old claim.
- `DELETE .../email/invitations/{id}`: revoke.
- `POST /_lanternfish/v2/claim`: `{ "token": "lfc_..." }`; returns a ticket.
- `GET/PUT /_lanternfish/admin/v2/jellyfin`: sanitized connection view / settings
  (`url`, `api_key`; blank key preserves the existing key for the same URL).
- `GET .../jellyfin/libraries`: library names and IDs.
- `GET/POST /_lanternfish/v2/jellyfin/account`: enrollment availability / create
  (`username`, `password`). POST requires a device session, same HTTPS Origin,
  and `X-Lanternfish-Account: create`.

Example optional ticket policy:

```json
{
  "platform": "web",
  "jellyfin_enrollment": {
    "libraries": ["0123456789abcdef0123456789abcdef"],
    "playback": true,
    "remote_access": true,
    "downloads": false,
    "transcoding": true
  }
}
```

The Tickets form also accepts an optional email recipient. Leaving it empty
creates the usual copyable ticket; supplying it queues a claim invitation using
the selected owner, policy and Jellyfin account permissions (email expiry is
limited to 60 minutes). Email settings must already be enabled.
