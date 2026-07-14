"""mimic CLI — capture any iOS app, generate a client.

    mimic record            start the proxy + print iPhone setup steps
    mimic hosts             list captured hosts (pick your API host here)
    mimic clear             permanently delete captured traffic
    mimic learn <host>      show the endpoints mimic saw for a host
    mimic gen <host>        AI-write a Python client for a host
    mimic unpin <ipa|id>    defeat cert pinning (Frida) so capture works
    mimic doctor            check your setup
"""
import argparse
import os
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys

from . import codegen
from . import proxy
from . import unpin
from .sources import mitm


def _mitm_and_flows():
    m = mitm.Mitm()
    return m, m.flows()


def _lan_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "<this-machine-ip>"
    finally:
        s.close()


def _mitmweb_cmd():
    """Prefer mitmweb on PATH; otherwise run it ephemerally through uv."""
    if shutil.which("mitmweb"):
        return ["mitmweb"]
    if shutil.which("uvx"):
        return ["uvx", "--from", "mitmproxy", "mitmweb"]
    return None


def _record_command(
    base, listen_host, proxy_port, web_port, web_token, proxy_credentials=None
):
    cmd = base + [
        "--listen-host",
        listen_host,
        "--listen-port",
        str(proxy_port),
        "--web-host",
        "127.0.0.1",
        "--web-port",
        str(web_port),
        "--set",
        f"web_password={web_token}",
        "--set",
        "web_open_browser=false",
    ]
    if proxy_credentials:
        username, password = proxy_credentials
        cmd += ["--set", f"proxyauth={username}:{password}"]
    return cmd


def _stop_process(proc):
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def cmd_record(args):
    ip = args.listen_host or _lan_ip()
    if ip == "<this-machine-ip>":
        sys.exit("couldn't determine a LAN address — pass --listen-host <ip>")

    existing = proxy.load_state()
    if existing and proxy.pid_is_running(existing.get("pid")):
        sys.exit(
            f"mimic record is already running (pid {existing['pid']}); "
            "stop it before starting another capture"
        )
    if existing:
        proxy.clear_state()

    web_token = os.environ.get("MITM_TOKEN") or secrets.token_urlsafe(32)
    credentials = None
    if not args.no_proxy_auth:
        credentials = ("mimic", secrets.token_hex(8))

    auth_steps = ""
    if credentials:
        auth_steps = f"""
        Authentication: ON
        Username: {credentials[0]}      Password: {credentials[1]}"""
    else:
        auth_steps = (
            "\n        Authentication: OFF "
            "(--no-proxy-auth; trusted LANs only)"
        )

    print(
        f"""
iPhone capture — do this once, then just reopen the app to add traffic:

  1. iPhone → Settings → Wi-Fi → (your network) ⓘ → Configure Proxy → Manual
        Server: {ip}      Port: {args.proxy_port}{auth_steps}
  2. Safari → http://mitm.it → download the Apple (.pem) profile
  3. Settings → General → VPN & Device Management → install the profile
  4. Settings → General → About → Certificate Trust Settings
        → turn ON full trust for "mitmproxy"          ← everyone forgets this
  5. open the target app and use it normally
  6. back here:   mimic hosts      then   mimic gen <api-host>

  mitmweb dashboard: http://127.0.0.1:{args.web_port}/?token={web_token}
  The proxy is bound to {ip}, not every network interface.

  Some apps (banks, Instagram) pin their certificate, so a proxy sees no
  usable traffic — those aren't supported. Many apps aren't pinned and just
  work; if `mimic hosts` shows the app's API host, you're good.
"""
    )
    cmd = _mitmweb_cmd()
    if not cmd:
        sys.exit(
            "no proxy available — install uv (https://astral.sh/uv) so mimic can\n"
            "run mitmproxy for you, or `pipx install mitmproxy` yourself."
        )
    cmd = _record_command(
        cmd, ip, args.proxy_port, args.web_port, web_token, credentials
    )
    sys.stdout.flush()  # show the steps before the proxy takes over the terminal
    proc = None
    old_sigterm = signal.getsignal(signal.SIGTERM)
    try:
        proc = subprocess.Popen(cmd)
        proxy.save_state(
            {
                "url": f"http://127.0.0.1:{args.web_port}",
                "token": web_token,
                "pid": proc.pid,
                "proxy_host": ip,
                "proxy_port": args.proxy_port,
            }
        )

        def forward_sigterm(signum, frame):
            if proc.poll() is None:
                proc.send_signal(signum)

        signal.signal(signal.SIGTERM, forward_sigterm)
        returncode = proc.wait()
        if returncode:
            sys.exit(f"mitmweb exited with status {returncode}")
    except KeyboardInterrupt:
        if proc:
            _stop_process(proc)
        print("\nproxy stopped")
    except FileNotFoundError:
        sys.exit("failed to launch mitmweb")
    finally:
        if proc:
            _stop_process(proc)
        signal.signal(signal.SIGTERM, old_sigterm)
        proxy.clear_state(token=web_token)


def cmd_doctor(args):
    ok = True

    def check(name, present, fix):
        nonlocal ok
        mark = "ok " if present else "MISSING"
        print(f"  [{mark}] {name}")
        if not present:
            ok = False
            print(f"          → {fix}")

    print("mimic setup check:\n")
    check("proxy (mitmweb or uvx)", _mitmweb_cmd() is not None,
          "install uv: curl -LsSf https://astral.sh/uv/install.sh | sh")
    check("AI generator (claude or opencode)",
          shutil.which("claude") is not None or shutil.which("opencode") is not None,
          "install Claude Code or OpenCode (https://opencode.ai), or use `mimic gen --prompt-only`")
    reachable = False
    try:
        mitm.Mitm().flows()
        reachable = True
    except mitm.MitmError:
        pass
    check("mitmweb running + reachable", reachable,
          "run `mimic record` in another terminal")

    def opt(name, present, fix):
        # Optional — only needed for `mimic unpin`; never fails the check.
        print(f"  [{'ok ' if present else '  -'}] {name}")
        if not present:
            print(f"          → {fix}")

    print("\noptional — only for `mimic unpin` (pinned apps):")
    opt("git (fetch unpinning scripts)", shutil.which("git") is not None,
        "install git (Xcode CLT: xcode-select --install)")
    opt("frida (run the hooks)", shutil.which("frida") is not None,
        "pipx install frida-tools   (or: uv tool install frida-tools)")
    opt("objection (gadget inject, no-JB path)", shutil.which("objection") is not None,
        "pipx install objection   (or: uv tool install objection)")

    print(f"\nLAN IP for the iPhone proxy: {_lan_ip()}:8080")
    sys.exit(0 if ok else 1)


def cmd_hosts(args):
    _, flows = _mitm_and_flows()
    rows = mitm.hosts(flows)
    if not rows:
        sys.exit("no traffic captured yet — run `mimic record` and use the app")
    print(f"{'requests':>9}  host")
    for host, n in rows:
        print(f"{n:>9}  {host}")
    print("\nPick your API host (usually the one with JSON, not media/cdn).")


def cmd_clear(args):
    m = mitm.Mitm()
    count = len(m.flows())
    m.clear()
    print(f"cleared {count} captured flow{'s' if count != 1 else ''}")


def cmd_learn(args):
    m, flows = _mitm_and_flows()
    eps = mitm.endpoints(m, flows, args.host)
    if not eps:
        sys.exit(f"no requests to {args.host} captured")
    print(f"{args.host}: {len(eps)} endpoints\n")
    for e in eps:
        print(f"  {e['method']:5s} {e['path']}   -> {e['status']}")


def cmd_gen(args):
    m, flows = _mitm_and_flows()
    eps = mitm.endpoints(m, flows, args.host)
    if not eps:
        sys.exit(f"no requests to {args.host} captured")

    if args.prompt_only:
        print(codegen.build_prompt(args.host, eps))
        return

    out = args.out or _default_out(args.host)
    print(f"asking {args.generator} to write a client from {len(eps)} endpoints…", file=sys.stderr)
    source = codegen.generate(args.host, eps, model=args.model, generator=args.generator)
    with open(out, "w") as f:
        f.write(source)
    cls = _class_name(source)
    print(f"\nwrote {out}")
    print(f"\n    from {out[:-3]} import {cls or 'Client'}")
    print(f"    acc = {cls or 'Client'}()")
    print("    # then call the generated methods\n")


def _default_out(host):
    stem = re.sub(r"[^a-z0-9]+", "_", host.split(".")[0].lower()).strip("_")
    return f"{stem or 'app'}_client.py"


def _class_name(source):
    m = re.search(r"class\s+(\w+)\s*\(", source)
    return m.group(1) if m else None


def main(argv=None):
    p = argparse.ArgumentParser(prog="mimic", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("doctor", help="check your setup").set_defaults(func=cmd_doctor)
    sub.add_parser("hosts", help="list captured hosts").set_defaults(func=cmd_hosts)
    sub.add_parser("clear", help="permanently delete captured flows").set_defaults(
        func=cmd_clear
    )

    rp = sub.add_parser("record", help="start the proxy + iPhone setup steps")
    rp.add_argument("--listen-host", help="LAN address to bind (default: auto-detect)")
    rp.add_argument("--proxy-port", type=int, default=8080)
    rp.add_argument("--web-port", type=int, default=8081)
    rp.add_argument(
        "--no-proxy-auth",
        action="store_true",
        help="disable proxy authentication (trusted LANs only)",
    )
    rp.set_defaults(func=cmd_record)

    lp = sub.add_parser("learn", help="show endpoints for a host")
    lp.add_argument("host")
    lp.set_defaults(func=cmd_learn)

    gp = sub.add_parser("gen", help="AI-generate a client for a host")
    gp.add_argument("host")
    gp.add_argument("-o", "--out", help="output .py path")
    gp.add_argument("--model", default="sonnet", help="model name (claude default: sonnet)")
    gp.add_argument("--generator", default="claude", choices=["claude", "opencode"],
                    help="AI generator to use (default: claude)")
    gp.add_argument("--prompt-only", action="store_true", help="print the prompt instead of calling the AI generator")
    gp.set_defaults(func=cmd_gen)

    up = sub.add_parser("unpin", help="defeat cert pinning via Frida so capture works")
    up.add_argument("target", help="a decrypted .ipa (gadget path) or app bundle-id (jailbroken path)")
    up.add_argument("--ca", help="mitmproxy CA cert (default: ~/.mitmproxy/mitmproxy-ca-cert.pem)")
    up.add_argument("--proxy-host", help="proxy host to bake in (default: this Mac's LAN IP)")
    up.add_argument("--workdir", help="where to put scripts + patched IPA (default: mimic-unpin/)")
    up.add_argument("--codesign", help="signing identity for `objection patchipa`")
    up.set_defaults(func=unpin.cmd_unpin)

    args = p.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
