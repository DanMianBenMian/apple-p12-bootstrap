#!/usr/bin/env python3
"""GSA probe 5: ablation against the CURRENT working implementation (nab138/isideload).

isideload (which just merged the 503 fix) still uses SRP A2k + base gsService URL, but adds
headers we were missing:
    X-Xcode-Version: 27.0 (27A5218g)
    X-Apple-App-Info: com.apple.gs.xcode.auth
    Connection: close
    Accept: text/x-xml-plist
    X-Mme-Client-Info: <Mac15,7> <macOS;27.0;26A5378j> <com.apple.AuthKit/1 (com.apple.akd/1.0)>
This probe adds them one at a time to find which one flips hsc 440 -> 200.
"""
import base64
import json
import os
import plistlib
import subprocess
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
    print("[p5]", *a, flush=True)


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


CI_AKD = "<MacBookPro18,3> <Mac OS X;%s;%s> <com.apple.akd/1.0 (com.apple.AOSKit/282)>" % (VER, BUILD)
CI_ILOAD = "<Mac15,7> <macOS;27.0;26A5378j> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
UA_AKD = "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0"
UA_XC = "Xcode"
BASE = "https://gsa.apple.com/grandslam/GsService2"
s = requests.Session()
s.trust_env = False

XCODE_HDRS = {"X-Xcode-Version": "27.0 (27A5218g)",
              "X-Apple-App-Info": "com.apple.gs.xcode.auth"}


def mkA():
    u = srp.User(REAL, b"", hash_alg=srp.SHA256, ng_type=srp.NG_2048)
    _, A = u.start_authentication()
    return A


def run(label, url=BASE, ci=CI_AKD, ua=UA_AKD, extra=None, accept="*/*", close=False):
    h = {"Content-Type": "text/x-xml-plist", "Accept": accept,
         "X-Mme-Client-Info": ci, "User-Agent": ua}
    if close:
        h["Connection"] = "close"
    if extra:
        h.update(extra)
    b = {"Header": {"Version": "1.0.1"},
         "Request": {"A2k": mkA(), "cpd": cpd(), "o": "init",
                     "ps": ["s2k", "s2k_fo"], "u": REAL}}
    try:
        r = s.post(url, data=plistlib.dumps(b), headers=h, verify=False, timeout=30)
    except Exception as e:
        log("%-46s EXC %s" % (label, e))
        return
    try:
        p = plistlib.loads(r.content)
    except Exception:
        log("%-46s HTTP %s non-plist %s" % (label, r.status_code, r.text[:120]))
        return
    resp = p.get("Response", p)
    st = resp.get("Status", {}) if isinstance(resp, dict) else {}
    ok = isinstance(resp, dict) and "s" in resp
    log("%-46s HTTP %s hsc=%s ec=%s em=%s%s" % (
        label, r.status_code, st.get("hsc"), st.get("ec"), st.get("em"),
        "   <<< SUCCESS" if ok else ""))
    if ok:
        log("     sp=%s i=%s" % (resp.get("sp"), resp.get("i")))


log("model ver build: %s %s %s" % (subprocess.run("sysctl -n hw.model", shell=True,
                                                  capture_output=True, text=True).stdout.strip(), VER, BUILD))

run("A baseline (akd ci, no extra hdrs)")
run("B + X-Xcode-Version + X-Apple-App-Info", extra=XCODE_HDRS)
run("C + Connection:close + Accept plist", accept="text/x-xml-plist", close=True)
run("D = B + C", extra=XCODE_HDRS, accept="text/x-xml-plist", close=True)
run("E = D + isideload client-info", ci=CI_ILOAD, extra=XCODE_HDRS,
    accept="text/x-xml-plist", close=True)
run("E2 = D + isideload ci, UA=Xcode", ci=CI_ILOAD, ua=UA_XC, extra=XCODE_HDRS,
    accept="text/x-xml-plist", close=True)
run("F = E but URL /init", url=BASE + "/init", ci=CI_ILOAD, extra=XCODE_HDRS,
    accept="text/x-xml-plist", close=True)
run("G = E but UA=Xcode only", ci=CI_ILOAD, ua=UA_XC, accept="text/x-xml-plist")
run("H isideload ci, UA=Xcode, no extra", ci=CI_ILOAD, ua=UA_XC)
log("DONE")
