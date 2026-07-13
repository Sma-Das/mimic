# mimic

Intercept any app, then call it from Python like a library.

```python
from hinge_client import Hinge

acc = Hinge()                 # reuses your captured session — no keys to wire up
recs = acc.get_recommendations()
acc.like(subject_id, comment="hi lol")
```

You never wrote `hinge_client.py`. mimic watched your own app traffic and an AI
wrote the client for you.

## How it works

Every app authenticates each request with a stable bundle — a bearer token,
device ids, a session id, cookies. Capture that once from a real request **you**
made, and you can craft new calls the server can't tell apart from the real app.

```
capture your traffic  ─▶  extract your reusable auth  ─▶  AI writes the client
     (mitmproxy)              (mimic.Session)              (claude reads the
                                                            captured endpoints)
```

The generated client is plain, editable Python on top of `mimic.App`. It gets
the ergonomic parts right — named methods, body templates, and the multi-step
chaining mobile APIs need (fetch a token here, spend it there).

## Install (one command)

```bash
sh install.sh
```

Installs [`uv`](https://astral.sh/uv) if you don't have it, then mimic in an
isolated tool env. No separate mitmproxy install — mimic launches it for you via
`uvx` on first `record`. (Manual: `uv tool install mimic-client`.)

```bash
mimic doctor                    # confirm proxy + claude are ready
```

## Use it (iPhone)

```bash
mimic record                    # starts the proxy, prints the exact iPhone steps
```

`record` walks you through it and auto-fills your Mac's LAN IP:

1. iPhone → Wi-Fi → Configure Proxy → Manual → `<your-mac-ip>:8080`
2. Safari → `http://mitm.it` → install the Apple profile
3. **Settings → General → About → Certificate Trust Settings → turn on full
   trust for mitmproxy** — the step everyone forgets
4. open the app, use it normally

Then:

```bash
mimic hosts                     # list captured hosts; pick your API host
mimic learn  prod-api.hingeaws.net    # see the endpoints mimic saw
mimic gen    prod-api.hingeaws.net    # AI writes hinge_client.py
```

Then `from hinge_client import Hinge; Hinge().get_recommendations()`.

## The library

Three ways to build a session by hand, if you don't want codegen:

```python
from mimic import Session

Session.from_mitm("prod-api.hingeaws.net")        # pull auth from mitmweb
Session.from_curl(open("copied.txt").read())      # paste "Copy as cURL" from devtools
Session(base_url="https://x.com", headers={...})  # explicit
```

`.get(path)` / `.post(path, json=...)` return parsed JSON and auto-refresh your
token from mitmweb if it rotates (a `401`/`403` triggers one re-pull + retry).

## Capture backends

- **mitmproxy** — iOS apps (the default). mimic reads its JSON flow API and runs
  it for you via `uvx`, so there's nothing extra to install.
- **cURL / paste** — anything with a web version. `Copy as cURL` in devtools →
  `Session.from_curl(text)`. No proxy, no cert.

**Certificate pinning** (banking, Instagram) defeats a plain proxy, so pinned
apps aren't supported. Plenty of apps aren't pinned and just work — if
`mimic hosts` shows the app's API host, you're set.

## Ethics

Use it on **your own** accounts and data. It replays *your* session; it is not a
tool for accessing anyone else's. Respect each app's terms of service.

## License

MIT — see [LICENSE](LICENSE). Provided as-is, no warranty. Use on your own
accounts and data; you are responsible for complying with each app's terms.
