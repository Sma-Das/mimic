# Certificate pinning

By default mimic captures traffic with a proxy (mitmproxy). A pinned app rejects
the proxy's cert, so the proxy sees nothing and there's nothing to capture. This
page is about getting past that.

## What pinning actually does

Worth being precise, because it changes the fix. Normal TLS authenticates the
*server* to the *client*: the app checks that the server's cert is signed by a
trusted CA. To MITM, you add your own CA to the device's trust store, and the
proxy presents a cert signed by it. Pinning breaks that by hardcoding the exact
cert (or public-key hash) the app will accept, so a proxy cert signed by *any*
CA — including one you control — is rejected.

Two things follow:

- **Pinning stops capture, not replay.** It only makes the traffic hard to
  *observe*. Once you can see a request, the auth bundle in it replays exactly
  as it would for an unpinned app. Pinning adds zero replay resistance — that's
  what DPoP is for (see [dpop.md](dpop.md)).
- **You can't beat it by feeding the app a cert.** The pinned value is a
  *public* cert; presenting it requires the matching private key, which lives on
  the server. The fix is app-side: make the app stop checking, by hooking its
  TLS verification at runtime with [Frida](https://frida.re).

mimic doesn't reimplement those hooks (a moving target across iOS versions and
TLS stacks). `mimic unpin` orchestrates the maintained upstream,
[httptoolkit/frida-interception-and-unpinning][ht], and owns the part that's
genuinely mimic's job: baking *your* mitmproxy CA and proxy address into the
scripts and emitting the exact command to run.

## Prerequisites

```bash
mimic doctor        # the "optional — only for mimic unpin" section
```

- **git** — fetches the unpinning scripts.
- **frida** — runs the hooks (`pipx install frida-tools`).
- **objection** — only for the no-jailbreak path (`pipx install objection`).
- A **mitmproxy CA** at `~/.mitmproxy/mitmproxy-ca-cert.pem`. Running
  `mimic record` once generates it.

## Path A — jailbroken device (simplest)

The phone runs `frida-server`; you attach over USB. No repackaging, no signing.

```bash
mimic record                       # in one terminal — starts the proxy
mimic unpin com.example.app        # bundle id → prints a ready frida command
```

`unpin` fetches the scripts, bakes in your CA + this Mac's LAN IP:8080, and
prints:

```bash
frida -U \
    -l mimic-unpin/frida-scripts/config.js \
    -l mimic-unpin/frida-scripts/ios/ios-connect-hook.js \
    -l mimic-unpin/frida-scripts/ios/ios-disable-detection.js \
    -l mimic-unpin/frida-scripts/native-tls-hook.js \
    -l mimic-unpin/frida-scripts/native-connect-hook.js \
    -f com.example.app
```

Run it, use the app, then the normal flow: `mimic hosts` → `mimic gen <host>`.

## Path B — stock device (Frida gadget)

No jailbreak. Inject the Frida gadget into a **decrypted** IPA, re-sign, sideload.

```bash
mimic unpin ./MyApp.ipa --codesign <TEAM_ID>
```

`unpin` bakes the config as above, then runs `objection patchipa` to inject the
gadget and writes `mimic-unpin/MyApp-patched.ipa`. mimic hands off the signing +
install step, because that's the Apple-auth swamp tools like Sideloadly exist to
handle:

- **easiest** — drag the patched IPA into [Sideloadly](https://sideloadly.io)
- **scripted** — `pymobiledevice3 apps install mimic-unpin/MyApp-patched.ipa`

Then attach the scripts to the gadget (`unpin` prints the exact `frida -U`
command) and capture as usual.

### The catches

- **Decrypted IPA required.** Your own app build is fine. An App Store app is
  FairPlay-encrypted; decrypting it needs a jailbroken device once (or a
  pre-decrypted IPA). "No jailbreak" often quietly means "no jailbreak *if
  someone already decrypted it*."
- **7-day cert churn.** Free Apple certs expire weekly.
  [TrollStore](https://github.com/opa334/TrollStore) (iOS ≤ 17.0.x) installs
  with real entitlements permanently and avoids the re-sign dance.
- **Anti-tamper.** Apps with binary-integrity checks detect the re-signed bundle
  and refuse to run.

## Framework notes

- **React Native** — uses `NSURLSession` and honors the system proxy. The
  standard hooks work.
- **Flutter** — ships its own BoringSSL and *ignores the system proxy*, so
  `SecTrustEvaluate` hooks never fire and setting a device proxy captures
  nothing. Needs [reFlutter](https://github.com/Impact-I/reFlutter) to patch the
  engine. `mimic unpin` won't handle Flutter apps as-is.

## What still won't work

Pinning is beatable; some things past it aren't:

- **DPoP / sender-constrained tokens** — the per-request signing key never
  leaves the device, so captured requests don't replay. See [dpop.md](dpop.md).
- **Certificate transparency / attestation** backed by hardware
  (App Attest / DeviceCheck) — out of scope.

[ht]: https://github.com/httptoolkit/frida-interception-and-unpinning
