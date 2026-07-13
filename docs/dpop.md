# DPoP / sender-constrained tokens

Unlike [cert pinning](pinning.md), this one defeats mimic's core model, not just
capture. If a target uses DPoP, static header replay does not work — by design.

## Why replay fails

A plain app authenticates every request with the same reusable bundle (a bearer
token, cookies, device ids). Capture it once, replay it forever — that's mimic.

DPoP ([RFC 9449][rfc]) breaks that. Every request carries a fresh `DPoP:` header:
a JWT signed by a private key the client holds, with claims that bind it to *that
one request*:

| Claim | Binds the proof to | Why a copy dies |
|-------|--------------------|-----------------|
| `htm` | HTTP method | reuse on another verb rejected |
| `htu` | request URL | reuse on another endpoint rejected |
| `iat` | issue time | server accepts only a few-second window |
| `jti` | unique id | server caches it; single-use |
| `nonce` | server-issued value | unpredictable, short-lived (§8) |
| `ath` | the access token | proof tied to that token |

The access token itself is bound to the key's thumbprint (`cnf.jkt`), so a stolen
token is useless without signing a matching proof *per request*. Copying the
header replays nothing.

## The only path: a signing oracle

You can't extract the key in the common case, but you might *borrow the app's
ability to use it*. Keep the app running on a device you control, hook its
DPoP-signing routine with Frida, and ask it to mint a fresh proof for each
request you want to send. It never touches the key — it uses the app as an
oracle. Whether this is even possible comes down to one fact:

| Key storage | Extractable? | Replay path |
|-------------|--------------|-------------|
| **Secure Enclave** (P-256, `kSecAttrTokenIDSecureEnclave`) — recommended, common | **No.** A jailbreak gives userland root, not silicon access. | Live Frida oracle only — tethered to the running app |
| **Keychain software key** (lazier apps) | **Yes**, on a jailbroken device (keychain-dumper, or a Frida `SecItemCopyMatching` hook) | Dump the key, sign proofs offline in Python |

So: fingerprint the target first. Dump the keychain, check whether the DPoP key
is Secure-Enclave-backed or a plain software key. That single fact decides
everything.

## The nonce problem

Even with a working oracle, RFC 9449 §8 nonces make offline replay impossible:
they're server-issued, opaque, and short-lived. You can't pre-mint proofs. Each
request becomes a live dance — send, get `use_dpop_nonce` + a fresh nonce, sign
with it, resend — with the device online the whole time. Fine for poking an API
interactively; useless for detached or scaled replay.

## Bottom line for mimic

- **Software key + jailbreak** → dump it, port the app's proof construction into
  Python, sign offline. Clean win (subject to the nonce dance).
- **Secure Enclave** → no extraction, ever. Best case is a live Frida oracle on a
  tethered jailbroken device. Not worth wiring into a general tool.
- **No device access** → infeasible. There is no network-only path.

There's no published DPoP-specific tooling (no Frida script, no mitmproxy addon);
you'd build the oracle from generic Frida hooking. Static header replay — the
thing mimic *is* — does not carry over to DPoP targets.

[rfc]: https://www.rfc-editor.org/rfc/rfc9449
