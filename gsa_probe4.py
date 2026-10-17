#!/usr/bin/env python3
"""GSA probe 4: the request is structurally fine (no-A2k -> "A is invalid.").
So focus on (a) what fetchAuthMode actually says, (b) how A must be encoded,
(c) whether SRP is still accepted at all."""
import base64
import json
import os
import plistlib
import subprocess
import time
from datetime import datetime, timezone

import requests
import urllib3

urllib3.disable_warnings()
import srp._pysrp as srp

srp.rfc5054_enable()
srp.no_username_in_x()
import objc  # noqa: E402
from Foundation import NSBundle, NSClassFromString  # noqa: E402

REAL = os.environ.get("APPLE_ID", "")
VER = subprocess.run("sw_vers -productVersion", shell=True, capture_output=True, text=True).stdout.strip()
BUILD = subprocess.run("sw_vers -buildVersion", shell=True, capture_output=True, text=True).stdout.strip()
SERIAL = subprocess.run(
    """ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformSerialNumber/{print $4}'""",
    shell=True, capture_output=True, text=True).stdout.strip()


def log(*a):
    print("[p4]", *a, flush=True)


_b = NSBundle.bundleWithPath_("/System/Library/PrivateFrameworks/AOSKit.framework")
_b.load()
objc.loadBundleFunctions(_b, globals(), [("retrieveOTPHeadersForDSID", b"")])
_AOS = NSClassFromString("AOSUtilities")


def ani():
    h = _AOS.retrieveOTPHeadersForDSID_("-2")
    return str(h["X-Apple-MD"]), str(h["X-Apple-MD-M"])


def now_iso():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def cpd():
    md, mdm = ani()
    return {"bootstrap": True, "icscrec": True, "pbe": False, "prkgen": True, "svct": "iCloud",
            "loc": "en_US", "X-Apple-Locale": "en_US",
            "X-Apple-I-MD": md, "X-Apple-I-MD-M": mdm,
            "X-Apple-I-MD-RINFO": "17106176",
            "X-Apple-I-MD-LU": base64.b64encode(b"0011223344").decode(),
            "X-Mme-Device-Id": "943768CA-CD2C-54E5-85BF-0A99977A25A6",
            "X-Apple-I-SRL-NO": SERIAL or "C02XL0XYJGH5",
            "X-Apple-I-Client-Time": now_iso(), "X-Apple-I-TimeZone": "UTC"}


CI = "<MacBookPro18,3> <Mac OS X;%s;%s> <com.apple.akd/1.0 (com.apple.AOSKit/282)>" % (VER, BUILD)
UA = "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0"
BASE = "https://gsa.apple.com/grandslam/GsService2"
s = requests.Session()
s.trust_env = False


def post(url, body, label, ci=CI, ua=UA, dump=False):
    h = {"Content-Type": "text/x-xml-plist", "Accept": "*/*",
         "X-Mme-Client-Info": ci, "User-Agent": ua}
    try:
        r = s.post(url, data=plistlib.dumps(body), headers=h, verify=False, timeout=30)
    except Exception as e:
        log("%s EXC %s" % (label, e))
        return None
    try:
        p = plistlib.loads(r.content)
    except Exception:
        log("%s HTTP %s non-plist %s" % (label, r.status_code, r.text[:150]))
        return None
    resp = p.get("Response", p) if isinstance(p, dict) else p
    if isinstance(resp, dict):
        st = resp.get("Status", {})
        log("%s HTTP %s keys=%s hsc=%s ec=%s em=%s" % (
            label, r.status_code, sorted(resp.keys())[:12],
            st.get("hsc") if isinstance(st, dict) else None,
            st.get("ec") if isinstance(st, dict) else None,
            st.get("em") if isinstance(st, dict) else None))
        if dump:
            log("   FULL: %s" % json.dumps(resp, default=str)[:1500])
    return resp


def mkA(user, pad=False, ng=srp.NG_2048):
    u = srp.User(user, b"", hash_alg=srp.SHA256, ng_type=ng)
    _, A = u.start_authentication()
    if pad and len(A) < 256:
        A = b"\x00" * (256 - len(A)) + A
    return A


# ---- 1. fetchAuthMode, full dump ----
log("---- 1 fetchAuthMode ----")
for lbl, extra in (("plain", {}), ("with-u", {"u": REAL, "o": "fetchAuthMode"})):
    b = {"Header": {"Version": "1.0.1"}, "Request": dict({"cpd": cpd()}, **extra)}
    post(BASE + "/fetchAuthMode", b, "fetchAuthMode %s" % lbl, dump=True)

# ---- 2. A encoding variants ----
log("---- 2 A variants ----")
for lbl, A in (("raw", mkA(REAL)),
               ("pad256", mkA(REAL, pad=True)),
               ("lstrip", mkA(REAL).lstrip(b"\x00"))):
    log("   len=%d first=%s last=%s" % (len(A), A[:4].hex(), A[-4:].hex()))
    b = {"Header": {"Version": "1.0.1"},
         "Request": {"A2k": A, "cpd": cpd(), "o": "init",
                     "ps": ["s2k", "s2k_fo"], "u": REAL}}
    post(BASE + "/init", b, "init A=%s" % lbl, dump=True)

# ---- 3. ps variants ----
log("---- 3 ps variants ----")
A = mkA(REAL)
for ps in (["s2k"], ["s2k_fo"], ["s2k", "s2k_fo"], []):
    b = {"Header": {"Version": "1.0.1"},
         "Request": {"A2k": A, "cpd": cpd(), "o": "init", "ps": ps, "u": REAL}}
    post(BASE + "/init", b, "init ps=%s" % (ps or "none"))

# ---- 4. svct variants ----
log("---- 4 svct / bootstrap variants ----")
for svct in ("iTunes", "iCloud"):
    c = cpd()
    c["svct"] = svct
    b = {"Header": {"Version": "1.0.1"},
         "Request": {"A2k": mkA(REAL), "cpd": c, "o": "init",
                     "ps": ["s2k", "s2k_fo"], "u": REAL}}
    post(BASE + "/init", b, "init svct=%s" % svct)

# ---- 5. what does the bag say gsService is ----
log("---- 5 bag gsService ----")
try:
    r = s.get(BASE + "/lookup", verify=False, timeout=20,
              headers={"X-Mme-Client-Info": CI, "User-Agent": "Xcode", "Accept": "*/*"})
    bag = plistlib.loads(r.content)
    u = bag.get("urls", {})
    for k in ("gsService", "fetchAuthMode", "pakeStep", "secondaryAuth",
              "trustedDeviceSecondaryAuth", "validateCode", "midStartProvisioning",
              "midSyncMachine", "qualifyCert", "fetchCertificate", "createCertificate"):
        log("   %-30s = %s" % (k, u.get(k)))
    log("   env = %s" % json.dumps(bag.get("env", {}), default=str)[:300])
except Exception as e:
    log("bag err %s" % e)

log("DONE")
