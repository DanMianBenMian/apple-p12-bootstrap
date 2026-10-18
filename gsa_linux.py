#!/usr/bin/env python3
"""gsa_linux.py - run the proven GSA/SRP flow from gsa_win.py, but source the
anisette from a LOCAL dadoum/anisette-server instead of the (now dead) Windows
anisette servers.

Why this path:
  - GitHub macOS runners are VirtualMac2,1 VMs -> AOSKit/anisette rejected
    (hsc=440 ec=-3000076).
  - Remote anisette servers (ani.jkcoxson.com, ani.stikstore.app, ...) are dead
    (434 / 500 / -80045).
  - dadoum/anisette-server runs on Linux using the Android libCoreADI.so and
    provisions a Mac-class ADI identity. This is the same anisette source
    AltServer-Linux / SideServer use. Whether Apple still accepts it post the
    2026-10-12 block is exactly what this probe tests (look for hsc in the log).
"""
import base64
import os
import sys
import uuid

import requests

import gsa_win  # the proven GSA/SRP implementation (do_init/do_complete/...)

# ---- config -------------------------------------------------------------
ANI_URL = (os.environ.get("ANI_URL") or "http://localhost:6969/").rstrip("/") + "/"
# override credentials if provided (else gsa_win's hardcoded test account is used)
if os.environ.get("APPLE_ID"):
    gsa_win.APPLE_ID = os.environ["APPLE_ID"]
if os.environ.get("APPLE_PASSWORD"):
    gsa_win.PASSWORD = os.environ["APPLE_PASSWORD"]

# Mac-class defaults (gsa_mac.py proven values). The anisette server usually
# returns its own client-info/rinfo; we fall back to these.
MAC_CLIENT_INFO = "<%s> <macOS;%s;%s> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
MAC_RINFO = "17106176"

# endpoints anisette servers expose (try them all, pick first with X-Apple-I-MD)
CANDIDATES = ["/", "/v1/anisette", "/headers", "/prov", "/anisette", ""]


def _fetch_anisette():
    s = requests.Session()
    s.trust_env = False
    last = None
    for path in CANDIDATES:
        try:
            url = ANI_URL.rstrip("/") + path
            r = s.get(url, timeout=20)
            if r.status_code != 200:
                last = (url, "http=%d" % r.status_code)
                continue
            try:
                j = r.json()
            except Exception:
                last = (url, "not-json(%d bytes)" % len(r.content))
                continue
            md = j.get("X-Apple-I-MD") or j.get("X-Apple-MD") or j.get("x-apple-i-md")
            if not md:
                last = (url, "no-MD keys=%s" % sorted(j.keys()))
                continue
            return url, j
        except Exception as e:
            last = (url, str(e)[:80])
    raise RuntimeError("no anisette endpoint returned X-Apple-I-MD; last=%s" % (last,))


def my_provision():
    url, j = _fetch_anisette()
    gsa_win.log("anisette from %s keys=%s" % (url, sorted(j.keys())))
    client_info = (j.get("X-Mme-Client-Info") or j.get("X-Apple-I-Client-Info")
                   or MAC_CLIENT_INFO)
    user_agent = j.get("User-Agent") or "akd/1.0 CFNetwork/808.1.4"
    rinfo = j.get("X-Apple-I-MD-RINFO") or MAC_RINFO
    state = {
        "server": ANI_URL,
        "client_info": client_info,
        "user_agent": user_agent,
        "device_id": j.get("X-Mme-Device-Id") or str(uuid.uuid4()).upper(),
        "identifier": base64.b64encode(os.urandom(16)).decode(),
        "rinfo": rinfo,
        "md": j.get("X-Apple-I-MD") or j.get("X-Apple-MD"),
        "md_m": j.get("X-Apple-I-MD-M") or j.get("X-Apple-I-MD-M"),
        "md_lu": j.get("X-Apple-I-MD-LU"),
        "extra": {k: v for k, v in j.items()
                  if k not in ("X-Apple-I-MD", "X-Apple-I-MD-M", "X-Apple-I-MD-RINFO",
                               "X-Apple-I-MD-LU", "X-Mme-Client-Info", "User-Agent",
                               "X-Mme-Device-Id")},
    }
    gsa_win.save_state(state)
    gsa_win.log("provisioned from local anisette: rinfo=%s md=%s..." %
                (state["rinfo"], (state["md"] or "")[:30]))
    return state


def my_refresh(s, st):
    try:
        _, j = _fetch_anisette()
        md = j.get("X-Apple-I-MD") or j.get("X-Apple-MD")
        if not md:
            gsa_win.log("refresh: no MD: %s" % sorted(j.keys()))
            return False
        st["md"] = md
        st["md_m"] = j.get("X-Apple-I-MD-M") or j.get("X-Apple-I-MD-M") or st.get("md_m")
        if j.get("X-Apple-I-MD-RINFO"):
            st["rinfo"] = j["X-Apple-I-MD-RINFO"]
        st.setdefault("extra", {}).update(
            {k: v for k, v in j.items()
             if k not in ("X-Apple-I-MD", "X-Apple-I-MD-M", "X-Apple-I-MD-RINFO",
                          "X-Apple-I-MD-LU")})
        gsa_win.save_state(st)
        gsa_win.log("refreshed MD: %s..." % st["md"][:28])
        return True
    except Exception as e:
        gsa_win.log("refresh failed: %s %s" % (type(e).__name__, str(e)[:140]))
        return False


# patch gsa_win's anisette source
gsa_win.provision = my_provision
gsa_win.refresh_headers = my_refresh


def _probe():
    s = requests.Session()
    s.trust_env = False
    my_provision()
    st = gsa_win.load_state()
    st = gsa_win.do_init(s, st)
    if st:
        gsa_win.log("*** GSA INIT ACCEPTED (anisette accepted by Apple) ***")
        return 0
    gsa_win.log("*** GSA INIT REJECTED (anisette NOT accepted) ***")
    return 1


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "probe"
    if cmd == "probe":
        sys.exit(_probe())
    # everything else: delegate to the proven main() (auth / submit / ...)
    gsa_win.main()
