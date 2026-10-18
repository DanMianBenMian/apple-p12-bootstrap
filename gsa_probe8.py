#!/usr/bin/env python3
"""probe8: complete CoreADI machine provisioning on the runner (Jkcoxson 'provision' flow),
then retry GSA init with the freshly-provisioned anisette.

Flow (from Jkcoxson sideloader pv_adi.d):
  midStartProvisioning (HTTP) -> spim
  ADIProvisioningStart(dsId, spim) -> cpim, session
  midFinishProvisioning (HTTP, cpim) -> ptm, tk, RINFO
  ADIProvisioningEnd(session, ptm, tk)          -> machine identity written
  ADIOTPRequest(dsId) -> otp + mid              -> REAL anisette
  GSA init with that anisette                   -> expect s+B (hsc=200 ec=0)

ADI hashed symbol map:
  kq56gsgHG6=LoadLibraryWithPath  Sph98paBcz=SetAndroidID  nf92ngaK92=SetProvisioningPath
  p435tmhbla=ProvisioningErase    tn46gtiuhw=Synchronize   fy34trz2st=ProvisioningDestroy
  uv5t6nhkui=ProvisioningEnd      rsegvyrt87=ProvisioningStart
  aslgmuibau=GetLoginCode         jk24uiwqrg=Dispose       qi864985u0=OTPRequest
"""
import base64
import ctypes
import glob
import hashlib
import hmac
import os
import plistlib
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone

import requests
import urllib3

urllib3.disable_warnings()

try:
    import srp._pysrp as srp
    srp.rfc5054_enable()
    srp.no_username_in_x()
except Exception as e:
    print("FATAL srp import: %s" % e, flush=True)
    sys.exit(1)

APPLE_ID = os.environ.get("APPLE_ID", "mocswpkddhxa@aniimate.net")
GS_LOOKUP = "https://gsa.apple.com/grandslam/GsService2/lookup"
APP_ID = "com.apple.gs.xcode.auth"
DSID = 0xFFFFFFFFFFFFFFFE  # -2 as ulong

MODEL = "Mac15,7"
CLIENT_INFO = "<%s> <macOS;15.7.9;24G830> <com.apple.AuthKit/1 (com.apple.akd/1.0)>" % MODEL
DEV_ID = str(uuid.uuid4()).upper()


def log(*a):
    print("[p8]", *a, flush=True)


def sh(cmd):
    try:
        return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30).stdout.strip()
    except Exception:
        return ""


# ---------------- 1. find a library exporting the ADI symbols ----------------
SYM_START, SYM_END, SYM_OTP, SYM_LOGIN = "rsegvyrt87", "uv5t6nhkui", "qi864985u0", "aslgmuibau"
SYM_SETID, SYM_SETPATH, SYM_LOADLIB, SYM_DISPOSE, SYM_DESTROY, SYM_ERASE, SYM_SYNC = (
    "Sph98paBcz", "nf92ngaK92", "kq56gsgHG6", "jk24uiwqrg", "fy34trz2st", "p435tmhbla", "tn46gtiuhw")

CANDIDATES = [
    "/System/Library/PrivateFrameworks/StoreServices.framework/StoreServices",
    "/System/Library/PrivateFrameworks/StoreServices.framework/Versions/A/StoreServices",
    "/System/Library/PrivateFrameworks/CoreADI.framework/CoreADI",
    "/usr/lib/libstoreservicescore.dylib",
]
CANDIDATES += glob.glob("/System/Library/PrivateFrameworks/*StoreServices*/**/*.dylib", recursive=True)
CANDIDATES += glob.glob("/System/Library/PrivateFrameworks/*CoreADI*/**/*.dylib", recursive=True)
CANDIDATES += sh("find /usr/lib /System/Library/PrivateFrameworks -maxdepth 4 -name 'libstoreservicescore*' 2>/dev/null").split()
CANDIDATES += sh("find /System/Library/PrivateFrameworks -maxdepth 3 -iname '*storeservices*' 2>/dev/null").split()

adi = None
adi_path = None
seen = set()
for c in CANDIDATES:
    if not c or c in seen or not os.path.exists(c):
        continue
    seen.add(c)
    try:
        lib = ctypes.CDLL(c)
        missing = []
        for s in (SYM_START, SYM_END, SYM_OTP, SYM_LOGIN, SYM_SETID, SYM_SETPATH,
                  SYM_DISPOSE, SYM_DESTROY, SYM_ERASE, SYM_SYNC):
            try:
                getattr(lib, s)
            except AttributeError:
                missing.append(s)
        log("lib %-70s missing=%s" % (c.replace("/System/Library/PrivateFrameworks/", "~/"), missing or "NONE"))
        if adi is None and not missing:
            adi, adi_path = lib, c
    except OSError as e:
        log("lib %-70s LOAD FAIL %s" % (c, e))

if adi is None:
    log("FATAL: no library with full ADI symbol set")
    sys.exit(3)
log("*** ADI LIBRARY: %s ***" % adi_path)

# prototypes
U = ctypes.c_uint64
UB = ctypes.c_ubyte
PUB = ctypes.POINTER(UB)
PPUB = ctypes.POINTER(PUB)
PU = ctypes.POINTER(ctypes.c_uint)
adi.__getattr__(SYM_START).argtypes = [U, PUB, ctypes.c_uint, PPUB, PU, PU]
adi.__getattr__(SYM_END).argtypes = [ctypes.c_uint, PUB, ctypes.c_uint, PUB, ctypes.c_uint]
adi.__getattr__(SYM_OTP).argtypes = [U, PPUB, PU, PPUB, PU]
adi.__getattr__(SYM_LOGIN).argtypes = [U]
adi.__getattr__(SYM_SETID).argtypes = [ctypes.c_char_p, ctypes.c_uint]
adi.__getattr__(SYM_SETPATH).argtypes = [ctypes.c_char_p]
adi.__getattr__(SYM_LOADLIB).argtypes = [ctypes.c_char_p]
adi.__getattr__(SYM_DISPOSE).argtypes = [ctypes.c_void_p]
adi.__getattr__(SYM_DESTROY).argtypes = [ctypes.c_uint]
adi.__getattr__(SYM_ERASE).argtypes = [U]
adi.__getattr__(SYM_SYNC).argtypes = [U, PUB, ctypes.c_uint, PPUB, PU, PPUB, PU]
for s in (SYM_START, SYM_END, SYM_OTP, SYM_LOGIN, SYM_SETID, SYM_SETPATH,
          SYM_LOADLIB, SYM_DISPOSE, SYM_DESTROY, SYM_ERASE, SYM_SYNC):
    adi.__getattr__(s).restype = ctypes.c_int

ADI_ERR = {-45061: "not provisioned", -45075: "library loading", -45063: "session pending",
           -45066: "session consumed", -45054: "fs error", -45046: "empty hw ids", -45036: "time error"}


def adierr(name, rc):
    log("  ADI %s -> %d %s" % (name, rc, ADI_ERR.get(rc, "")))
    return rc


# ---------------- 2. init ADI ----------------
IDENT = uuid.uuid4().hex[:16].upper()
PROV_DIR = os.path.join(os.environ.get("RUNNER_TEMP", "/tmp"), "adiprov")
os.makedirs(PROV_DIR, exist_ok=True)
LU_UUID = hashlib.sha256(IDENT.encode()).digest()
LU_UUID = str(uuid.uuid3(uuid.NAMESPACE_DNS, IDENT)).upper()

adierr("SetAndroidID", adi.__getattr__(SYM_SETID)(IDENT.encode(), len(IDENT)))
adierr("SetProvisioningPath", adi.__getattr__(SYM_SETPATH)(PROV_DIR.encode()))
rc = adierr("LoadLibraryWithPath(skip?)", adi.__getattr__(SYM_LOADLIB)(PROV_DIR.encode()))
if rc != 0:
    for p in ("/System/Library/PrivateFrameworks/CoreADI.framework",
              "/System/Library/PrivateFrameworks", "/usr/lib"):
        if adi.__getattr__(SYM_LOADLIB)(p.encode()) == 0:
            log("  LoadLibraryWithPath OK with %s" % p)
            break

lc = adierr("GetLoginCode", adi.__getattr__(SYM_LOGIN)(DSID))
log("machine provisioned = %s" % (lc == 0))


# ---------------- 3. provisioning loop ----------------
def prov_headers():
    return {"User-Agent": "akd/1.0 CFNetwork/1404.0.5 Darwin/22.3.0",
            "Content-Type": "application/x-www-form-urlencoded",
            "Connection": "keep-alive",
            "X-Mme-Device-Id": DEV_ID,
            "X-MMe-Client-Info": CLIENT_INFO,
            "X-Apple-I-MD-LU": LU_UUID,
            "X-Apple-Client-App-Name": "Setup",
            "X-Apple-I-Client-Time": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")}


RINFO = "17106176"
if lc != 0:
    s = requests.Session()
    s.trust_env = False
    bag = plistlib.loads(requests.get(GS_LOOKUP, headers={
        "User-Agent": "akd/1.0 CFNetwork/1404.0.5 Darwin/22.3.0",
        "X-Mme-Client-Info": CLIENT_INFO}, verify=False, timeout=30).content)["urls"]
    url_start, url_finish = bag["midStartProvisioning"], bag["midFinishProvisioning"]
    log("midStart=%s" % url_start)

    empty = plistlib.dumps({"Header": {}, "Request": {}})
    r1 = s.post(url_start, data=empty, headers=prov_headers(), verify=False, timeout=30)
    p1 = plistlib.loads(r1.content)
    st1 = p1.get("Status", {})
    log("midStart http=%s ec=%s em=%s" % (r1.status_code, st1.get("ec"), st1.get("em")))
    spim = base64.b64decode(p1["Response"]["spim"])
    log("spim %d bytes" % len(spim))

    cpim_ptr = PUB(); cpim_len = ctypes.c_uint(0); session = ctypes.c_uint(0)
    buf = (UB * len(spim)).from_buffer_copy(spim)
    adierr("ProvisioningStart", adi.__getattr__(SYM_START)(
        DSID, ctypes.cast(buf, PUB), len(spim),
        ctypes.byref(cpim_ptr), ctypes.byref(cpim_len), ctypes.byref(session)))
    cpim = ctypes.string_at(cpim_ptr, cpim_len.value)
    log("cpim %d bytes session=%d" % (len(cpim), session.value))

    body = plistlib.dumps({"Header": {}, "Request": {"cpim": base64.b64encode(cpim).decode()}})
    r2 = s.post(url_finish, data=body, headers=prov_headers(), verify=False, timeout=30)
    p2 = plistlib.loads(r2.content)
    st2 = p2.get("Status", {})
    log("midFinish http=%s ec=%s em=%s" % (r2.status_code, st2.get("ec"), st2.get("em")))
    resp2 = p2["Response"]
    RINFO = str(resp2.get("X-Apple-I-MD-RINFO", RINFO))
    ptm = base64.b64decode(resp2["ptm"])
    tk = base64.b64decode(resp2["tk"])
    log("ptm %d bytes tk %d bytes RINFO=%s" % (len(ptm), len(tk), RINFO))

    ptm_buf = (UB * len(ptm)).from_buffer_copy(ptm)
    tk_buf = (UB * len(tk)).from_buffer_copy(tk)
    adierr("ProvisioningEnd", adi.__getattr__(SYM_END)(
        session.value, ctypes.cast(ptm_buf, PUB), len(ptm),
        ctypes.cast(tk_buf, PUB), len(tk)))
    adi.__getattr__(SYM_DESTROY)(session.value)

    lc = adierr("GetLoginCode(after)", adi.__getattr__(SYM_LOGIN)(DSID))
    log("machine provisioned(after) = %s" % (lc == 0))
    if lc != 0:
        log("FATAL: provisioning did not stick")
        sys.exit(4)


# ---------------- 4. request OTP -> real anisette ----------------
mid_ptr = PUB(); mid_len = ctypes.c_uint(0)
otp_ptr = PUB(); otp_len = ctypes.c_uint(0)
adierr("OTPRequest", adi.__getattr__(SYM_OTP)(
    DSID, ctypes.byref(mid_ptr), ctypes.byref(mid_len),
    ctypes.byref(otp_ptr), ctypes.byref(otp_len)))
OTP = ctypes.string_at(otp_ptr, otp_len.value)
MID = ctypes.string_at(mid_ptr, mid_len.value)
log("*** OTP %d bytes, MID %d bytes (REAL anisette) ***" % (len(OTP), len(MID)))
log("otp_b64=%s" % base64.b64encode(OTP).decode()[:44])
log("mid_b64=%s" % base64.b64encode(MID).decode()[:44])


# ---------------- 5. GSA init with the new anisette ----------------
def now_iso():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def cpd():
    return {"bootstrap": True, "icscrec": True, "pbe": False, "prkgen": True,
            "svct": "iCloud", "loc": "en_US", "X-Apple-Locale": "en_US",
            "X-Apple-I-MD": base64.b64encode(OTP).decode(),
            "X-Apple-I-MD-M": base64.b64encode(MID).decode(),
            "X-Apple-I-MD-RINFO": RINFO,
            "X-Apple-I-MD-LU": base64.b64encode(LU_UUID.encode()).decode(),
            "X-Mme-Device-Id": DEV_ID,
            "X-Mme-Client-Info": CLIENT_INFO,
            "X-Apple-I-SRL-NO": "0",
            "X-Apple-I-Client-Time": now_iso(),
            "X-Apple-I-TimeZone": "UTC"}


def ghdr():
    return {"Content-Type": "text/x-xml-plist", "Accept": "text/x-xml-plist",
            "X-Mme-Client-Info": CLIENT_INFO, "User-Agent": "akd/1.0",
            "X-Xcode-Version": "27.0 (27A5218g)", "X-Apple-App-Info": APP_ID,
            "Connection": "close"}


s = requests.Session()
s.trust_env = False
u = srp.User(APPLE_ID, b"", hash_alg=srp.SHA256, ng_type=srp.NG_2048)
_, A = u.start_authentication()
body = {"Header": {"Version": "1.0.1"},
        "Request": {"A2k": A, "cpd": cpd(), "o": "init", "ps": ["s2k", "s2k_fo"], "u": APPLE_ID}}
r = s.post("https://gsa.apple.com/grandslam/GsService2", data=plistlib.dumps(body),
           headers=ghdr(), verify=False, timeout=30)
resp = plistlib.loads(r.content)["Response"]
st = resp.get("Status", {})
log("GSA init http=%s hsc=%s ec=%s em=%s" % (r.status_code, st.get("hsc"), st.get("ec"), st.get("em")))
if "s" in resp and "B" in resp:
    log("*** *** *** SUCCESS: s+B received — SRP started! *** *** ***")
    log("salt=%s iters=%s proto=%s" % (base64.b64encode(resp['s']).decode()[:16], resp.get('i'), resp.get('sp')))
else:
    log("init keys: %s" % sorted(resp.keys()))
log("DONE")
