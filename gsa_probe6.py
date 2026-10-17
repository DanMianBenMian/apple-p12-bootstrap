#!/usr/bin/env python3
"""GSA probe 6: is our ANISETTE the thing Apple is rejecting?

Controls:
  1. init with GOOD anisette          -> (known) hsc=440 ec=-3000076
  2. init with CORRUPTED X-Apple-I-MD -> if the error CHANGES, Apple IS validating
     our anisette (and it currently passes). If identical, anisette is not the gate.
  3. init with NO anisette at all     -> same idea
  4. midStartProvisioning             -> does Apple know / accept this machine? (needs
     native ADI to finish, but the error tells us if our MID is unknown)
  5. syncMachine                      -> same
  6. Enumerate macOS ADI / AOSKit capabilities so we know what native tools exist.
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


def log(*a):
    print("[p6]", *a, flush=True)


def sh(c, t=25):
    try:
        return subprocess.run(c, shell=True, capture_output=True, text=True, timeout=t).stdout.strip()
    except Exception as e:
        return "(err %s)" % e


# ---- 6. enumerate native capabilities FIRST (cheap, no network) ----
log("---- frameworks ----")
log(sh("ls /System/Library/PrivateFrameworks | grep -iE 'adi|deviceidentity|authkit|aos|anisette|appleid|akd'"))
log("---- AOSKit exported symbols ----")
sym = sh("nm -gU /System/Library/PrivateFrameworks/AOSKit.framework/AOSKit 2>/dev/null | grep -iE 'otp|provision|machine|adi|mid|anisette|serial|uuid' | head -40")
log(sym or "(none)")
log("---- AOSKit classes ----")
log(sh("strings /System/Library/PrivateFrameworks/AOSKit.framework/AOSKit | grep -E '^AOS[A-Za-z]+$' | sort -u | head -40"))
log("---- AOSUtilities selectors ----")
log(sh("strings /System/Library/PrivateFrameworks/AOSKit.framework/AOSKit | grep -iE 'retrieveOTP|provision|syncMachine|machineInfo' | sort -u | head -30"))
log("---- akd / authkit binaries ----")
log(sh("ls /System/Library/PrivateFrameworks/AuthKit.framework 2>/dev/null | head"))
log(sh("which akd; ls -d /usr/libexec/akd 2>/dev/null; ls /System/Library/PrivateFrameworks | wc -l"))

VER = sh("sw_vers -productVersion")
BUILD = sh("sw_vers -buildVersion")
SERIAL = sh("""ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformSerialNumber/{print $4}'""")
log("model=%s ver=%s build=%s serial=%s" % (sh("sysctl -n hw.model"), VER, BUILD, SERIAL))

_b = NSBundle.bundleWithPath_("/System/Library/PrivateFrameworks/AOSKit.framework")
_b.load()
objc.loadBundleFunctions(_b, globals(), [("retrieveOTPHeadersForDSID", b"")])
_AOS = NSClassFromString("AOSUtilities")


def ani():
    h = _AOS.retrieveOTPHeadersForDSID_("-2")
    return str(h["X-Apple-MD"]), str(h["X-Apple-MD-M"])


def now_iso():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def mkcpd(mode="good"):
    md, mdm = ani()
    c = {"bootstrap": True, "icscrec": True, "pbe": False, "prkgen": True, "svct": "iCloud",
         "loc": "en_US", "X-Apple-Locale": "en_US",
         "X-Apple-I-MD-RINFO": "17106176",
         "X-Apple-I-MD-LU": base64.b64encode(b"0011223344").decode(),
         "X-Mme-Device-Id": "943768CA-CD2C-54E5-85BF-0A99977A25A6",
         "X-Apple-I-SRL-NO": SERIAL or "C02XL0XYJGH5",
         "X-Apple-I-Client-Time": now_iso(), "X-Apple-I-TimeZone": "UTC"}
    if mode == "good":
        c["X-Apple-I-MD"] = md
        c["X-Apple-I-MD-M"] = mdm
    elif mode == "corrupt":
        c["X-Apple-I-MD"] = base64.b64encode(b"AAAA" * 8).decode()
        c["X-Apple-I-MD-M"] = mdm
    elif mode == "none":
        pass
    return c


CI = "<Mac15,7> <macOS;27.0;26A5378j> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
UA = "Xcode"
BASE = "https://gsa.apple.com/grandslam/GsService2"
s = requests.Session()
s.trust_env = False


def post(url, body, label, hdr_extra=None, dump=True):
    h = {"Content-Type": "text/x-xml-plist", "Accept": "text/x-xml-plist",
         "X-Mme-Client-Info": CI, "User-Agent": UA,
         "X-Xcode-Version": "27.0 (27A5218g)",
         "X-Apple-App-Info": "com.apple.gs.xcode.auth"}
    if hdr_extra:
        h.update(hdr_extra)
    try:
        r = s.post(url, data=plistlib.dumps(body), headers=h, verify=False, timeout=30)
    except Exception as e:
        log("%-40s EXC %s" % (label, e))
        return
    try:
        p = plistlib.loads(r.content)
    except Exception:
        log("%-40s HTTP %s non-plist %s" % (label, r.status_code, r.text[:120]))
        return
    resp = p.get("Response", p)
    log("%-40s HTTP %s  %s" % (label, r.status_code,
                               json.dumps(resp, default=str)[:400] if dump else ""))
    return resp


def mkA():
    u = srp.User(REAL, b"", hash_alg=srp.SHA256, ng_type=srp.NG_2048)
    _, A = u.start_authentication()
    return A


log("---- 1/2/3 anisette controls ----")
for mode in ("good", "corrupt", "none"):
    b = {"Header": {"Version": "1.0.1"},
         "Request": {"A2k": mkA(), "cpd": mkcpd(mode), "o": "init",
                     "ps": ["s2k", "s2k_fo"], "u": REAL}}
    post(BASE, b, "init anisette=%s" % mode)

log("---- 4 midStartProvisioning ----")
post("https://gsa.apple.com/grandslam/MidService/startMachineProvisioning",
     {"Header": {}, "Request": {"cpd": mkcpd()}}, "midStartProvisioning")

log("---- 5 syncMachine ----")
post("https://gsa.apple.com/grandslam/MidService/syncMachine",
     {"Header": {}, "Request": {"cpd": mkcpd()}}, "syncMachine")

log("DONE")
