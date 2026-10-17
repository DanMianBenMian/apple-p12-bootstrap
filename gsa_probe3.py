#!/usr/bin/env python3
"""GSA probe 3: discriminate WHY init returns hsc=440 / ec=-3000076.

Tests:
  A. dump every key AOSKit returns (maybe we're missing an anisette field)
  B. fetchAuthMode -> what does Apple say this account must use?
  C. init with the REAL account  vs  init with a BOGUS account (control)
       Apple returns a fake s+B for unknown accounts. So:
         bogus -> s+B  and real -> 440   =>  ACCOUNT problem (locked / rate-limited)
         bogus -> 440   and real -> 440   =>  REQUEST / DEVICE problem
  D. init without A2k (see if the error changes)
  E. full cfgs dump (look for oakRidge / spake / srp deprecation flags)
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

REAL = os.environ.get("APPLE_ID", "")
BOGUS = "zzqq-nonexistent-%d@icloud.com" % (int(time.time()) % 100000)
VER = subprocess.run("sw_vers -productVersion", shell=True, capture_output=True, text=True).stdout.strip()
BUILD = subprocess.run("sw_vers -buildVersion", shell=True, capture_output=True, text=True).stdout.strip()
MODEL = subprocess.run("sysctl -n hw.model", shell=True, capture_output=True, text=True).stdout.strip()
SERIAL = subprocess.run(
    """ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformSerialNumber/{print $4}'""",
    shell=True, capture_output=True, text=True).stdout.strip()


def log(*a):
    print("[p3]", *a, flush=True)


_b = NSBundle.bundleWithPath_("/System/Library/PrivateFrameworks/AOSKit.framework")
_b.load()
objc.loadBundleFunctions(_b, globals(), [("retrieveOTPHeadersForDSID", b"")])
_AOS = NSClassFromString("AOSUtilities")

# ---- A. full AOSKit dump ----
h0 = _AOS.retrieveOTPHeadersForDSID_("-2")
log("AOSKit header keys: %s" % sorted(h0.keys()))
for k in sorted(h0.keys()):
    v = str(h0[k])
    log("   %-28s = %s%s" % (k, v[:60], " ...(%d)" % len(v) if len(v) > 60 else ""))


def ani():
    h = _AOS.retrieveOTPHeadersForDSID_("-2")
    return str(h["X-Apple-MD"]), str(h["X-Apple-MD-M"])


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


CI_AKD = "<MacBookPro18,3> <Mac OS X;%s;%s> <com.apple.akd/1.0 (com.apple.AOSKit/282)>" % (VER, BUILD)
CI_XC = "<MacBookPro18,3> <Mac OS X;%s;%s> <com.apple.AOSKit/282 (com.apple.dt.Xcode/3594.4.19)>" % (VER, BUILD)
UA_AKD = "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0"
BASE = "https://gsa.apple.com/grandslam/GsService2"
s = requests.Session()
s.trust_env = False


def post(url, body, ci=CI_AKD, ua=UA_AKD, label=""):
    h = {"Content-Type": "text/x-xml-plist", "Accept": "*/*",
         "X-Mme-Client-Info": ci, "User-Agent": ua}
    try:
        r = s.post(url, data=plistlib.dumps(body), headers=h, verify=False, timeout=30)
    except Exception as e:
        log("%s EXC %s" % (label, e))
        return None
    log("%s HTTP %s" % (label, r.status_code))
    try:
        p = plistlib.loads(r.content)
    except Exception:
        log("   non-plist: %s" % r.text[:200])
        return None
    resp = p.get("Response", p)
    st = resp.get("Status", {})
    log("   keys=%s hsc=%s ec=%s em=%s" % (sorted(resp.keys())[:12], st.get("hsc"), st.get("ec"), st.get("em")))
    return resp


def init_body(user, with_a2k=True):
    req = {"cpd": cpd(), "o": "init", "ps": ["s2k", "s2k_fo"], "u": user}
    if with_a2k:
        u = srp.User(user, b"", hash_alg=srp.SHA256, ng_type=srp.NG_2048)
        _, A = u.start_authentication()
        req["A2k"] = A
    return {"Header": {"Version": "1.0.1"}, "Request": req}


# ---- B. fetchAuthMode ----
log("---- B: fetchAuthMode ----")
post(BASE + "/fetchAuthMode", init_body(REAL), label="fetchAuthMode real")
post(BASE + "/fetchAuthMode", init_body(BOGUS), label="fetchAuthMode bogus")

# ---- C. init: bogus control first, then real ----
log("---- C: init control ----")
r_bogus = post(BASE + "/init", init_body(BOGUS), label="init BOGUS(control)")
if r_bogus and "s" in r_bogus:
    log("   >>> CONTROL OK: Apple returned fake salt for unknown account")
r_real = post(BASE + "/init", init_body(REAL), label="init REAL")
if r_real and "s" in r_real:
    log("   >>> REAL OK")

# ---- C2. same but with the Xcode client-info (the classic string) ----
post(BASE + "/init", init_body(BOGUS), ci=CI_XC, ua="Xcode", label="init BOGUS xcode-ci")
post(BASE + "/init", init_body(REAL), ci=CI_XC, ua="Xcode", label="init REAL  xcode-ci")

# ---- D. init without A2k ----
log("---- D: init no A2k ----")
post(BASE + "/init", init_body(REAL, with_a2k=False), label="init REAL no-A2k")
post(BASE + "/init", init_body(BOGUS, with_a2k=False), label="init BOGUS no-A2k")

# ---- E. full cfgs ----
log("---- E: bag cfgs ----")
try:
    r = s.get(BASE + "/lookup", verify=False, timeout=20,
              headers={"X-Mme-Client-Info": CI_XC, "User-Agent": "Xcode", "Accept": "*/*"})
    bag = plistlib.loads(r.content)
    cfgs = bag.get("cfgs", {})
    log("cfgs keys: %s" % sorted(cfgs.keys()))
    for k in sorted(cfgs.keys()):
        v = json.dumps(cfgs[k], default=str)
        if any(t in k.lower() for t in ("oak", "spake", "srp", "pake", "auth", "2fa", "lock", "mode")):
            log("   * %-40s = %s" % (k, v[:300]))
    log("urls keys: %s" % sorted(bag.get("urls", {}).keys()))
except Exception as e:
    log("bag err %s" % e)

log("DONE")
