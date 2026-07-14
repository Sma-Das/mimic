"""Read captured traffic from a running mitmweb instance.

mitmweb exposes a JSON API on http://127.0.0.1:8081. Auth is a bearer token sent
once to establish a session cookie; subsequent requests reuse the cookie. This
module pulls the raw flows and normalizes them into a shape that both the
runtime Session and the AI codegen step can consume.
"""
import json
import os

import requests

from .. import proxy


DEFAULT_URL = "http://127.0.0.1:8081"


class MitmError(RuntimeError):
    pass


class Mitm:
    """A thin client over a running mitmweb's flow API."""

    def __init__(self, url=None, token=None):
        state = proxy.load_state() or {}
        configured_url = url or os.environ.get("MITM_URL")
        env_token = os.environ.get("MITM_TOKEN")
        if configured_url:
            # Never send a token loaded for mimic's local proxy to an unrelated
            # explicitly configured URL.
            self.url = configured_url.rstrip("/")
            self.token = token if token is not None else env_token
        else:
            self.url = (state.get("url") or DEFAULT_URL).rstrip("/")
            self.token = (
                token
                if token is not None
                else env_token or state.get("token")
            )
        self._http = requests.Session()

    def _auth(self):
        try:
            headers = (
                {"Authorization": f"Bearer {self.token}"} if self.token else {}
            )
            r = self._http.get(f"{self.url}/", headers=headers, timeout=5)
        except requests.RequestException as e:
            raise MitmError(
                f"can't reach mitmweb at {self.url} — is it running? "
                f"start it with `mimic record` (original error: {e})"
            )
        if r.status_code != 200:
            raise MitmError(
                f"mitmweb authentication failed with {r.status_code} — "
                "start it with `mimic record`, or set MITM_TOKEN for a "
                "manually managed proxy"
            )

    def flows(self):
        """All captured flows as a list of dicts (mitmweb's own schema)."""
        self._auth()
        r = self._http.get(f"{self.url}/flows", timeout=15)
        if r.status_code != 200:
            raise MitmError(f"mitmweb /flows returned {r.status_code}")
        return r.json()

    def body(self, flow_id, side):
        """Raw request/response body bytes for a flow. side is 'request' or 'response'."""
        r = self._http.get(
            f"{self.url}/flows/{flow_id}/{side}/content.data", timeout=15
        )
        if r.status_code != 200:
            raise MitmError(f"mitmweb flow body returned {r.status_code}")
        return r.content

    def clear(self):
        """Permanently remove all in-memory flows and events from mitmweb."""
        self._auth()
        xsrf = self._http.cookies.get("_mitmproxy_xsrf") or self._http.cookies.get(
            "_xsrf"
        )
        headers = {"X-XSRFToken": xsrf} if xsrf else {}
        r = self._http.post(f"{self.url}/clear", headers=headers, timeout=15)
        if r.status_code not in (200, 204):
            raise MitmError(f"mitmweb /clear returned {r.status_code}")


def _headers_dict(req):
    return {k: v for k, v in req.get("headers", [])}


def hosts(flows):
    """Count requests per host, most frequent first."""
    counts = {}
    for f in flows:
        req = f.get("request")
        if req:
            counts[req["host"]] = counts.get(req["host"], 0) + 1
    return sorted(counts.items(), key=lambda kv: -kv[1])


def endpoints(mitm, flows, host):
    """Distinct (method, path) endpoints for a host, with a sample req/resp body.

    Returns a list of dicts ready to feed to the AI. Latest capture of each
    endpoint wins, so bodies reflect the most recent real call.
    """
    by_key = {}
    for f in flows:
        req = f.get("request")
        if not req or req["host"] != host:
            continue
        by_key[(req["method"], req["path"].split("?")[0])] = f

    out = []
    for (method, path), f in by_key.items():
        req = f.get("request") or {}
        resp = f.get("response") or {}
        out.append(
            {
                "method": method,
                "path": path,
                "status": resp.get("status_code"),
                "query": req["path"].split("?", 1)[1] if "?" in req["path"] else "",
                "request_body": _decode(mitm.body(f["id"], "request")),
                "response_body": _decode(mitm.body(f["id"], "response")),
            }
        )
    return out


def _decode(raw, limit=4000):
    """Best-effort decode of a body to a truncated JSON/text string for the AI."""
    if not raw:
        return ""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return f"<{len(raw)} bytes binary>"
    try:  # pretty-print + truncate JSON so the AI sees structure, not noise
        text = json.dumps(json.loads(text), indent=2)
    except ValueError:
        pass
    return text[:limit] + ("\n…(truncated)" if len(text) > limit else "")
