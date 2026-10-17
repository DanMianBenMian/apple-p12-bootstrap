#!/usr/bin/env python3
"""GSA init probe: try many client-identity / endpoint variants, dump everything.
Goal: find which combination makes /grandslam/GsService2 init return s+B instead of
      hsc=440 / ec=-3000076.
No 2FA needed for this stage - init only does the SRP handshake start.
"""
import base64
import json
import os
import plistlib
import subprocess
import sys
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

APPLE_ID = os.environ.get("APPLE_ID", "")
VER = subprocess.run("sw_vers -productVersion", shell=True, capture_output=True, text=True).stdout.strip()
BUILD = subprocess.run("sw_vers -buildVersion", shell=True, capture_output=True, text=True).stdout.strip()
MODEL = subprocess.run("sysctl -n hw.model", shell=True, capture_output=True, text=True).stdout.strip()
SERIAL = subprocess.run(
    """ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformSerialNumber/{print $4}'""",
    shell=True, capture_output=True, text=True).stdout.strip()


def log(*a):
    print("[probe]", *a, flush=True)


log("model=%s ver=%s build=%s serial=%s" % (MODEL, VER, BUILD, SERIAL))

_b = NSBundle.bundleWithPath_("/System/Library/PrivateFrameworks/AOSKit.framework")
if _b is None or not _b.load():
    log("FATAL: no AOSKit")
    sys.exit(2)
objc.loadBundleFunctions(_b, globals(), [("retrieveOTPHeadersForDSID", b"")])
_AOS = NSClassFromString("AOSUtilities")


def ani():
    h = _AOS.retrieveOTPHeadersForDSID_("-2")
    return str(h["X-Apple-MD"]), str(h["X-Apple-MD-M"])


md0, mdm0 = ani()
log("AOSKit OK  X-Apple-MD=%s... (%d chars)  MD-M=%s... (%d chars)"
    % (md0[:24], len(md0), mdm0[:24], len(mdm0)))
md1, mdm1 = ani()
log("second OTP identical to first? %s" % (md0 == md1))


def now_iso():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def cpd():
    md, mdm = ani()
    return {
        "bootstrap": True, "icscrec": True, "pbe": False, "prkgen": True, "svct": "iCloud",
        "loc": "en_US", "X-Apple-Locale": "en_US",
        "X-Apple-I-MD": md, "X-Apple-I-MD-M": mdm,
        "X-Apple-I-MD-RINFO": "17106176",
        "X-Apple-I-MD-LU": base64.b64encode(b"0011223344").decode(),
        "X-Mme-Device-Id": "943768CA-CD2C-54E5-85BF-0A99977A25A6",
        "X-Apple-I-SRL-NO": SERIAL or "C02XL0XYJGH5",
        "X-Apple-I-Client-Time": now_iso(),
        "X-Apple-I-TimeZone": "UTC",
    }


def init_body():
    u = srp.User(APPLE_ID, b"", hash_alg=srp.SHA256, ng_type=srp.NG_2048)
    _, A = u.start_authentication()
    return {"Header": {"Version": "1.0.1"},
            "Request": {"A2k": A, "cpd": cpd(), "o": "init",
                        "ps": ["s2k", "s2k_fo"], "u": APPLE_ID}}


# ---------- 0) the lookup bag = Apple's authoritative endpoint table ----------
BAG = {}
for ci in ("<MacBookPro18,3> <Mac OS X;%s;%s> <com.apple.AOSKit/282 (com.apple.dt.Xcode/3594.4.19)>" % (VER, BUILD),
           "<%s> <Mac OS X;%s;%s> <com.apple.AOSKit/282 (com.apple.dt.Xcode/3594.4.19)>" % (MODEL, VER, BUILD)):
    try:
        r = requests.get("https://gsa.apple.com/grandslam/GsService2/lookup", verify=False, timeout=20,
                         headers={"X-Mme-Client-Info": ci, "User-Agent": "Xcode", "Accept": "*/*"})
        log("lookup HTTP=%s  ci=%s" % (r.status_code, ci[:60]))
        if r.status_code == 200:
            try:
                BAG = plistlib.loads(r.content)
                log("BAG KEYS: %s" % sorted(BAG.keys()))
                log("BAG urls: %s" % json.dumps(BAG.get("urls", {}), default=str)[:2000])
                log("BAG FULL: %s" % json.dumps(BAG, default=str)[:3000])
                break
            except Exception as e:
                log("bag parse fail %s %s" % (e, r.text[:300]))
        else:
            log("bag body: %s" % r.text[:200])
    except Exception as e:
        log("lookup err %s" % e)

# ---------- variants ----------
BASE = "https://gsa.apple.com/grandslam/GsService2"
CI_XCODE_VM = "<%s> <Mac OS X;%s;%s> <com.apple.AOSKit/282 (com.apple.dt.Xcode/3594.4.19)>" % (MODEL, VER, BUILD)
CI_XCODE_REAL = "<MacBookPro18,3> <Mac OS X;%s;%s> <com.apple.AOSKit/282 (com.apple.dt.Xcode/3594.4.19)>" % (VER, BUILD)
CI_AKD = "<MacBookPro18,3> <Mac OS X;%s;%s> <com.apple.akd/1.0 (com.apple.AOSKit/282)>" % (VER, BUILD)
CI_AKD2 = "<MacBookPro18,3> <Mac OS X;%s;%s> <com.apple.AOSKit/282 (com.apple.dt.Xcode/3594.4.19)>" % (VER, BUILD)

BAA = {"X-Apple-Baa-E": "-10000", "X-Apple-Baa-Avail": "2",
       "X-Apple-Host-Baa-E": "-7066",
       "X-Apple-Baa-UE": "AKAuthenticationError:-7066|com.apple.devicecheck.error.baa:-10000",
       "X-Apple-Client-App-Name": "akd", "Accept-Language": "en-US,en;q=0.9"}

VARIANTS = [
    ("1 ctrl  base / Xcode-UA / VM-model", BASE, CI_XCODE_VM, "Xcode", {}, {}),
    ("2       base / Xcode-UA / MBP18,3", BASE, CI_XCODE_REAL, "Xcode", {}, {}),
    ("3       /init / Xcode-UA / MBP18,3", BASE + "/init", CI_XCODE_REAL, "Xcode", {}, {}),
    ("4       base / akd-UA / com.apple.akd", BASE, CI_AKD,
     "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0", {}, {}),
    ("5       base / akd-UA / BAA headers", BASE, CI_AKD2,
     "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0", BAA, {}),
    ("6       base / akd-UA / BAA + json", BASE, CI_AKD,
     "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0", BAA, {"Content-Type": "application/x-www-form-urlencoded"}),
]

results = []
for name, url, ci, ua, extra, over in VARIANTS:
    body = init_body()
    h = {"Content-Type": "text/x-xml-plist", "Accept": "*/*",
         "X-Mme-Client-Info": ci, "User-Agent": ua}
    h.update(extra)
    h.update(over)
    try:
        s = requests.Session()
        s.trust_env = False
        r = s.post(url, data=plistlib.dumps(body), headers=h, verify=False, timeout=30)
    except Exception as e:
        log("%-42s -> EXC %s" % (name, e))
        results.append((name, "EXC", str(e)[:100]))
        continue
    line = "%-42s -> HTTP %s" % (name, r.status_code)
    log(line)
    interesting = {k: v for k, v in r.headers.items()
                   if k.lower().startswith("x-apple") or k.lower().startswith("x-mme")}
    if interesting:
        log("    resp hdrs: %s" % json.dumps(interesting, default=str)[:600])
    try:
        p = plistlib.loads(r.content)
        resp = p.get("Response", p)
        st = resp.get("Status", {})
        ok = ("s" in resp and "B" in resp)
        log("    keys=%s  hsc=%s ec=%s em=%s  -> %s"
            % (sorted(resp.keys()), st.get("hsc"), st.get("ec"), st.get("em"),
               "SUCCESS s+B" if ok else "fail"))
        if ok:
            log("    *** VARIANT %s WORKS ***  sp=%s i=%s" % (name, resp.get("sp"), resp.get("i")))
            results.append((name, "SUCCESS", url + " || " + ci + " || " + ua))
        else:
            results.append((name, "hsc=%s ec=%s" % (st.get("hsc"), st.get("ec")), str(st.get("em"))[:120]))
    except Exception as e:
        log("    non-plist (%s): %s" % (e, r.text[:200]))
        results.append((name, "http%s" % r.status_code, r.text[:120]))
    time.sleep(1)

log("======== SUMMARY ========")
for n, st, extra in results:
    log("%-42s : %s %s" % (n, st, extra))
log("DONE")
