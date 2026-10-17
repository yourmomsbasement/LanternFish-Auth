# Periodic factor reauthentication (0.4.1)

In **Policy → Additional verification**, set **Reauthenticate after (seconds;
0 disables)** and choose **Factors for periodic reauthentication**. The same
settings are available in profile and device override policy editors.

For example, `86400` with **authenticator code** requires a successful TOTP
verification on each device at least every 24 hours. Choose **passkey** for
WebAuthn instead, or select both to require both. Enable the selected methods
below and enroll the owner's factors before enabling the policy. Recovery codes
remain available wherever the existing verification flow permits them.

The interval is the maximum elapsed time since successful factor verification,
not inactivity time. Ordinary traffic, session renewal, and device-key proofs do
not extend it. Each device records separate timestamps for each factor type;
verification on another device does not extend this device's access. Successful
factor verification during enrollment also counts. Email invitation delivery
and ticket redemption alone do not count as factor verification.

Zero (the default) preserves previous behavior. Values from 1 to 31,536,000
seconds are supported. A nonzero interval requires at least one enabled factor.
Existing devices with no verification history must verify on their next access.
Tightening a policy applies to existing credentials as well as new sign-ins.

At the deadline, clients must prove their device key and complete the existing
verification flow. Browsers use the verification page; native clients use the
existing `/v2/session` and verification endpoints. Certificate authentication
alone cannot bypass it. Sessions and certificate grants expire by this deadline;
open streams also end at it in both continuity and strict modes. Schedule,
revocation, owner, country and other hard restrictions still apply.

If another rule already requires verification, its factors are combined with
the periodic factors. All configured periodic factors are requested together
when any is stale, giving the device a full interval after completion.
Timestamps are persisted in the device record, so restarting the Gate does not
reset the timer. Existing verification audit events record successful factors.

JSON policy fields:

```json
{
  "verification": {
    "reauthenticate_after_seconds": 86400,
    "reauthenticate_required_all": ["totp"]
  }
}
```

These fields belong inside the complete policy object. Other verification
settings and enabled factor policies remain required as before.
