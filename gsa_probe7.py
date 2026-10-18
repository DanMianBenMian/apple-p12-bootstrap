#!/usr/bin/env python3
"""GSA probe 7: does ANY GitHub runner image present a machine identity Apple accepts?

GitHub macOS-15 ARM runners are VirtualMac2,1 (Apple Virtualization) and get hsc=440/
ec=-3000076. macOS-13/14 Intel runners may be bare-metal Macs with a real ADI identity.
This prints hw.model and tries init on each image.
"""
import base64
import os
import plistlib
import subprocess
import sys
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
    print("[p7]", *a, flush=True)


VER = subprocess.run("sw_vers -productVersion", shell=True, capture_output=True, text=True).stdout.strip()
BUILD = subprocess.run("sw_vers -buildVersion", shell=True, capture_output=True, text=True).stdout.strip()
MODEL = subprocess.run("sysctl -n hw.model", shell=True, capture_output=True, text=True).stdout.strip()
SERIAL = subprocess.run(
    """ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformSerialNumber/{print $4}'""",
    shell=True, capture_output=True, text=True).stdout.strip()

_b = NSBundle.bundleWithPath_("/System/Library/PrivateFrameworks/AOSKit.framework")
_b.load()
objc.loadBundleFunctions(_b, globals(), [("retrieveOTPHeadersForDSID", b"")])
_AOS = NSClassFromString("AOSUtilities")


def ani():
    h = _AOS.retrieveOTPHeadersForDSID_("-2")
    return str(h["X-Apple-MD"]), str(h["X-Apple-MD-M"])


def now_iso():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


log("image hw.model=%s ver=%s build=%s serial=%s" % (MODEL, VER, BUILD, SERIAL))


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


BASE = "https://gsa.apple.com/grandslam/GsService2"
s = requests.Session()
s.trust_env = False


def mkA():
    u = srp.User(REAL, b"", hash_alg=srp.SHA256, ng_type=srp.NG_2048)
    _, A = u.start_authentication()
    return A


for label, ci in (
        ("self", "<%s> <Mac OS X;%s;%s> <com.apple.akd/1.0 (com.apple.AOSKit/282)>" % (MODEL, VER, BUILD)),
        ("isideload", "<Mac15,7> <macOS;27.0;26A5378j> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"),
):
    h = {"Content-Type": "text/x-xml-plist", "Accept": "text/x-xml-plist",
         "X-Mme-Client-Info": ci, "User-Agent": "Xcode",
         "X-Xcode-Version": "27.0 (27A5218g)", "X-Apple-App-Info": "com.apple.gs.xcode.auth"}
    b = {"Header": {"Version": "1.0.1"},
         "Request": {"A2k": mkA(), "cpd": cpd(), "o": "init",
                     "ps": ["s2k", "s2k_fo"], "u": REAL}}
    try:
        r = s.post(BASE, data=plistlib.dumps(b), headers=h, verify=False, timeout=30)
        p = plistlib.loads(r.content)
        resp = p.get("Response", p)
        st = resp.get("Status", {})
        ok = "s" in resp and "B" in resp
        log("init[%-10s] HTTP %s hsc=%s ec=%s em=%s %s" % (
            label, r.status_code, st.get("hsc"), st.get("ec"), st.get("em"),
            "<<< SUCCESS s+B" if ok else ""))
    except Exception as e:
        log("init[%s] EXC %s" % (label, e))

log("DONE")
