# Cirreum.Authentication.SignedRequest 1.0.8

One fix. No API changed, nothing to recompile, and nothing to do unless a credential in your store
has a blank `Audience`.

## A blank `Audience` is now refused, loudly

`StoredSigningCredential.Audience` uses `null` as the sentinel for "no explicit audience binding" —
the credential's `keyid` is then its own implicit audience and no `tag` is required. An empty string
is a different thing: it says the credential *is* bound, while naming nothing to bind to.

Left alone, that matched only a request carrying an explicitly empty `tag`, which no ordinary caller
sends. The credential therefore rejected everyone, and the rejection surfaced as an audience mismatch
— which reads as a signature or configuration problem at the *caller*, not as a malformed row in the
credential store.

It is now refused at resolution with a warning naming the credential and the fix. **This is not a
security change** — a caller still needed the signing secret to get that far, and the old behaviour
failed closed. What changes is that a misconfiguration now announces itself instead of presenting as
an unexplained outage for one client.

**What to check:** if a credential should have no audience binding, leave `Audience` as `null`. If it
should be bound, set the audience it is bound to. A blank string was never meaningful and now says so.

## Why it surfaced

A sweep across the authentication packages for a blank-value comparison pattern found in
`Cirreum.Authentication.External`, where a blank configured audience could match a blank token
audience — an acceptance where none was configured. The equivalent shape here fails closed rather
than open, so it is a diagnosability fix rather than a hole. `Cirreum.Authentication.ApiKey` got the
matching guard on its credential comparison in the same sweep.

The core signing path needed nothing: `HmacSha256SignedRequestAlgorithm.Verify` compares a computed
fixed-width MAC against the supplied signature with an explicit length check, so neither side can be
empty. That is the general shape — comparing a computed hash is structurally immune; comparing a
supplied value against a stored one is where the blank case has to be handled explicitly.

## Compatibility

- No public type, method, or signature changed
- Signature verification, replay protection, and nonce handling are unchanged
- Credentials with a `null` or a real `Audience` behave exactly as before

## See also

- [`docs/CHANGELOG.md`](CHANGELOG.md)
