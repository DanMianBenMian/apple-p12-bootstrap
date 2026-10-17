#!/usr/bin/env python3
"""Free iOS Development certificate via GSA, using NATIVE macOS AOSKit anisette.

Pipeline:
  1. anisette  : AOSKit retrieveOTPHeadersForDSID_("-2")  (real Apple ADI)
  2. GSA login : /grandslam/GsService2 init -> complete (SRP-6a) -> 2FA -> apptokens
  3. portal    : developerservices2.apple.com/services/QH65B2/*.action?clientId=XABBG36SBA
                 auth = X-Apple-I-Identity-Id (adsid) + X-Apple-GS-Token (app token)
  4. cert      : generate RSA key + CSR -> submitDevelopmentCSR.action -> .cer
  5. export    : openssl pkcs12 -export -> dev.p12
"""
import base64
import hashlib
import hmac
import json
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
except Exception as e:  # pragma: no cover
    print("FATAL: srp import failed: %s" % e, flush=True)
    sys.exit(1)

from cryptography import x509
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import NameOID

APPLE_ID = os.environ["APPLE_ID"]
PASSWORD = os.environ["APPLE_PASSWORD"]
APP_ID = "com.apple.gs.xcode.auth"
GS = "https://gsa.apple.com/grandslam/GsService2"
PROTO = "QH65B2"
CLIENT_ID = "XABBG36SBA"
DEVBASE = "https://developerservices2.apple.com/services/%s/" % PROTO
CODE_URL = os.environ.get("CODE_POLL_URL", "")
GH_PAT = os.environ.get("GH_PAT", "")
OUT = os.environ.get("RUNNER_TEMP", "/tmp")


def log(*a):
    print("[mac]", *a, flush=True)


# ---------------- native macOS anisette ----------------
import objc  # noqa: E402
from Foundation import NSBundle, NSClassFromString  # noqa: E402

_b = NSBundle.bundleWithPath_("/System/Library/PrivateFrameworks/AOSKit.framework")
if _b is None or not _b.load():
    log("FATAL: AOSKit.framework unavailable")
    sys.exit(2)
objc.loadBundleFunctions(_b, globals(), [("retrieveOTPHeadersForDSID", b"")])
_AOS = NSClassFromString("AOSUtilities")


def anisette():
    h = _AOS.retrieveOTPHeadersForDSID_("-2")
    return h["X-Apple-MD"], h["X-Apple-MD-M"]


def sh(cmd, dflt=""):
    try:
        o = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30).stdout.strip()
        return o or dflt
    except Exception:
        return dflt


VER = sh("sw_vers -productVersion", "15.7.9")
BUILD = sh("sw_vers -buildVersion", "24G830")
MODEL = sh("sysctl -n hw.model", "MacBookPro18,3")
SERIAL = sh("""ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformSerialNumber/{print $4}'""", "C02XL0XYJGH5")
HWUUID = sh("""ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'""", str(uuid.uuid4()).upper())
CLIENT_INFO = "<%s> <Mac OS X;%s;%s> <com.apple.AOSKit/282 (com.apple.dt.Xcode/3594.4.19)>" % (MODEL, VER, BUILD)
log("client_info = %s" % CLIENT_INFO)
log("serial=%s hwuuid=%s" % (SERIAL, HWUUID))


def now_iso():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def cpd():
    md, mdm = anisette()
    return {
        "bootstrap": True, "icscrec": True, "pbe": False, "prkgen": True, "svct": "iCloud",
        "loc": "en_US", "X-Apple-Locale": "en_US",
        "X-Apple-I-MD": md, "X-Apple-I-MD-M": mdm,
        "X-Apple-I-MD-RINFO": "17106176",
        "X-Apple-I-MD-LU": base64.b64encode(b"0011223344").decode(),
        "X-Mme-Device-Id": HWUUID,
        "X-Apple-I-SRL-NO": SERIAL,
        "X-Apple-I-Client-Time": now_iso(),
        "X-Apple-I-TimeZone": "UTC",
    }


def ghdr():
    return {"Content-Type": "text/x-xml-plist", "Accept": "*/*",
            "X-Mme-Client-Info": CLIENT_INFO, "User-Agent": "Xcode"}


# ---------------- GSA ----------------
def srp_user():
    return srp.User(APPLE_ID, b"", hash_alg=srp.SHA256, ng_type=srp.NG_2048)


def enc_pw(salt, iters, proto):
    p = hashlib.sha256(PASSWORD.encode()).digest()
    if proto == "s2k_fo":
        p = p.hex().encode()
    return hashlib.pbkdf2_hmac("sha256", p, salt, iters, 32)


def gsa_init(s, tries=4):
    for t in range(tries):
        u = srp_user()
        _, A = u.start_authentication()
        body = {"Header": {"Version": "1.0.1"},
                "Request": {"A2k": A, "cpd": cpd(), "o": "init",
                            "ps": ["s2k", "s2k_fo"], "u": APPLE_ID}}
        r = s.post(GS + "/init", data=plistlib.dumps(body), headers=ghdr(), verify=False, timeout=30)
        try:
            resp = plistlib.loads(r.content)["Response"]
        except Exception as e:
            log("init parse fail %s %s" % (e, r.text[:300]))
            return None
        st = resp.get("Status", {})
        log("init hsc=%s ec=%s em=%s" % (st.get("hsc"), st.get("ec"), st.get("em")))
        if st.get("hsc") == 434:
            log("  434 resync -> fresh anisette, retry %d/%d" % (t + 1, tries))
            continue
        if "s" in resp and "B" in resp:
            return {"u": u, "salt": resp["s"], "B": resp["B"],
                    "i": resp["i"], "sp": resp["sp"], "c": resp["c"]}
        log("init unexpected keys: %s" % sorted(resp.keys()))
        return None
    return None


def gsa_complete(s, stt):
    u = stt["u"]
    u.p = enc_pw(stt["salt"], stt["i"], stt["sp"])
    M1 = u.process_challenge(stt["salt"], stt["B"])
    if M1 is None:
        log("process_challenge failed (bad password?)")
        return None
    body = {"Header": {"Version": "1.0.1"},
            "Request": {"M1": M1, "c": stt["c"], "cpd": cpd(), "o": "complete", "u": APPLE_ID}}
    r = s.post(GS + "/complete", data=plistlib.dumps(body), headers=ghdr(), verify=False, timeout=30)
    try:
        resp = plistlib.loads(r.content)["Response"]
    except Exception as e:
        log("complete parse fail %s %s" % (e, r.text[:400]))
        return None
    st = resp.get("Status", {})
    log("complete hsc=%s ec=%s em=%s au=%s" % (st.get("hsc"), st.get("ec"), st.get("em"), st.get("au")))
    out = {"hsc": st.get("hsc", 0), "au": st.get("au", "")}
    if "spd" in resp:
        K = u.get_session_key()
        ek = hmac.new(K, b"extra data key:", hashlib.sha256).digest()
        ei = hmac.new(K, b"extra data iv:", hashlib.sha256).digest()[:16]
        dec = Cipher(algorithms.AES(ek), modes.CBC(ei)).decryptor()
        data = dec.update(resp["spd"]) + dec.finalize()
        unp = padding.PKCS7(128).unpadder()
        try:
            spd = plistlib.loads(unp.update(data) + unp.finalize())
        except Exception as e:
            log("spd unpad/parse fail: %s" % e)
            return out
        log("spd keys: %s" % sorted(spd.keys()))
        out.update(adsid=spd.get("adsid"), idmsToken=spd.get("GsIdmsToken"),
                   sk=spd.get("sk"), c=spd.get("c"))
    return out


def wait_code(exclude=None, timeout=420):
    log("waiting up to %ds for 2FA code (exclude=%s)" % (timeout, exclude))
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            h = {"User-Agent": "curl/8", "Cache-Control": "no-cache"}
            if GH_PAT:
                h["Authorization"] = "Bearer " + GH_PAT
            r = requests.get(CODE_URL, headers=h, timeout=15)
            v = base64.b64decode(r.json()["content"]).decode().strip()
            if len(v) == 6 and v.isdigit() and v != exclude:
                log("GOT CODE %s" % v)
                return v
        except Exception as e:
            log("poll err: %s %s" % (type(e).__name__, str(e)[:80]))
        time.sleep(5)
    log("2FA wait TIMED OUT")
    return None


def anis_hdr(extra=None):
    md, mdm = anisette()
    h = {"X-Apple-I-MD": md, "X-Apple-I-MD-M": mdm, "X-Apple-I-MD-RINFO": "17106176",
         "X-Apple-I-Client-Time": now_iso(), "X-Apple-Locale": "en_US", "X-Apple-I-TimeZone": "UTC"}
    if extra:
        h.update(extra)
    return h


def sendcode(s, adsid, idmsToken):
    ident = base64.b64encode(("%s:%s" % (adsid, idmsToken)).encode()).decode()
    h = dict(ghdr())
    h.update(anis_hdr({"X-Apple-Identity-Token": ident}))
    r = s.get("https://gsa.apple.com/auth/verify/trusteddevice", headers=h, verify=False, timeout=30)
    log("sendcode http=%s %s" % (r.status_code, r.text[:200]))
    return r.status_code == 200, ident


def submitcode(s, ident, code):
    h = dict(ghdr())
    h.update(anis_hdr({"X-Apple-Identity-Token": ident, "security-code": code}))
    r = s.get(GS + "/validate", headers=h, verify=False, timeout=30)
    log("validate http=%s %s" % (r.status_code, r.text[:300]))
    try:
        v = plistlib.loads(r.content)
        log("validate ec=%s em=%s" % (v.get("ec"), v.get("em")))
        return v.get("ec") == 0
    except Exception:
        return False


def apptokens(s, adsid, idmsToken, sk, c):
    checksum = hmac.new(sk, b"apptokens" + adsid.encode() + APP_ID.encode(), hashlib.sha256).digest()
    body = {"Header": {"Version": "1.0.1"},
            "Request": {"u": adsid, "app": [APP_ID], "c": c, "t": idmsToken,
                        "checksum": checksum, "cpd": cpd(), "o": "apptokens"}}
    r = s.post(GS + "/apptokens", data=plistlib.dumps(body), headers=ghdr(), verify=False, timeout=30)
    log("apptokens http=%s" % r.status_code)
    try:
        resp = plistlib.loads(r.content)["Response"]
    except Exception as e:
        log("apptokens parse fail %s %s" % (e, r.text[:300]))
        return None
    log("apptokens Status: %s keys=%s" % (resp.get("Status"), sorted(resp.keys())))
    et = resp.get("et")
    if not et or et[:3] != b"XYZ":
        log("no/et bad header: %r" % (et[:8] if et else None))
        return None
    tok = plistlib.loads(AESGCM(sk).decrypt(et[3:19], et[19:], b"XYZ"))
    token = tok["t"][APP_ID]["token"]
    log("*** APP TOKEN len=%d ***" % len(token))
    return token


# ---------------- developer portal ----------------
def dev_post(s, service, body, adsid, token, segs=("", "ios/")):
    for seg in segs:
        md, mdm = anisette()
        h = {"Content-Type": "text/x-xml-plist", "Accept": "text/x-xml-plist",
             "Accept-Language": "en-us", "User-Agent": "Xcode",
             "X-Apple-I-Identity-Id": adsid, "X-Apple-GS-Token": token,
             "X-Apple-I-MD": md, "X-Apple-I-MD-M": mdm,
             "X-Apple-I-MD-LU": base64.b64encode(b"0011223344").decode(),
             "X-Apple-I-Client-Time": now_iso(), "X-Apple-Locale": "en_US",
             "X-Apple-I-TimeZone": "UTC", "X-Mme-Client-Info": CLIENT_INFO}
        url = DEVBASE + seg + service + "?clientId=" + CLIENT_ID
        try:
            r = s.post(url, data=plistlib.dumps(body), headers=h, verify=False, timeout=40)
        except Exception as e:
            log("  dev_post %s%s err %s" % (seg, service, e))
            continue
        log("  %s%s -> HTTP %s" % (seg, service, r.status_code))
        try:
            p = plistlib.loads(r.content)
            log("  keys=%s" % sorted(p.keys())[:14])
            log("  RAW=%s" % json.dumps(p, default=str)[:1200])
            return p
        except Exception:
            log("  non-plist: %s" % r.text[:300])
    return None


def make_csr():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([
               x509.NameAttribute(NameOID.COMMON_NAME, "RyConsole Free Dev"),
               x509.NameAttribute(NameOID.ORGANIZATION_NAME, "DanMianBenMian"),
               x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
           ]))
           .sign(key, hashes.SHA256()))
    return key, csr.public_bytes(serialization.Encoding.PEM).decode()


# ---------------- main ----------------
def main():
    s = requests.Session()
    s.trust_env = False

    stt = gsa_init(s)
    if not stt:
        log("FATAL init failed")
        return 1
    res = gsa_complete(s, stt)
    if not res:
        log("FATAL complete failed")
        return 1

    if res.get("hsc") == 409:
        log("2FA required (au=%s)" % res.get("au"))
        ok, ident = sendcode(s, res["adsid"], res["idmsToken"])
        log("code pushed: %s" % ok)
        code = wait_code()
        if not code:
            return 1
        if not submitcode(s, ident, code):
            log("code rejected")
            return 1
        log("code accepted -> relogin")
        stt = gsa_init(s)
        if not stt:
            return 1
        res = gsa_complete(s, stt)
        if not res:
            return 1
        log("relogin hsc=%s" % res.get("hsc"))

    if not res.get("adsid") or not res.get("sk"):
        log("FATAL no adsid/sk: %s" % {k: (str(v)[:20] if v else None) for k, v in res.items()})
        return 1

    token = apptokens(s, res["adsid"], res["idmsToken"], res["sk"], res["c"])
    if not token:
        log("FATAL no app token")
        return 1

    adsid = res["adsid"]
    log("authenticated. adsid=%s" % adsid)

    dev_post(s, "viewDeveloper.action", {}, adsid, token, segs=("",))
    teams_p = dev_post(s, "listTeams.action", {}, adsid, token, segs=("",))
    teams = (teams_p or {}).get("teams") or []
    if not teams:
        log("NO TEAMS")
        return 1
    team = teams[0]
    team_id = team.get("teamId")
    log("team: id=%s name=%s type=%s" % (team_id, team.get("name"), team.get("type")))

    key, csr_pem = make_csr()
    log("CSR generated (%d bytes)" % len(csr_pem))
    body = {"teamId": team_id, "machineId": str(uuid.uuid4()).upper(),
            "machineName": "RyConsole-Free-Dev", "csrContent": csr_pem}
    resp = dev_post(s, "submitDevelopmentCSR.action", body, adsid, token, segs=("ios/", ""))
    if not resp:
        log("submitDevelopmentCSR failed")
        return 1

    # dig the certificate out of whatever Apple returned
    cr = resp.get("certRequest") or {}
    log("certRequest keys: %s" % sorted(cr.keys()))
    cert_pem = None
    for k, v in cr.items():
        if isinstance(v, str) and ("-----BEGIN" in v):
            cert_pem = v
            log("found cert PEM in certRequest[%s]" % k)
            break
    if not cert_pem:
        # maybe the cert is top-level
        for k, v in resp.items():
            if isinstance(v, str) and "-----BEGIN" in v:
                cert_pem = v
                log("found cert PEM in resp[%s]" % k)
                break

    key_path = os.path.join(OUT, "dev_key.pem")
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))

    if cert_pem:
        cer_path = os.path.join(OUT, "dev.pem")
        with open(cer_path, "w") as f:
            f.write(cert_pem)
        p12 = os.path.join(OUT, "dev.p12")
        cmd = ('openssl pkcs12 -export -out "%s" -inkey "%s" -in "%s" '
               '-passout pass: -name "iOS Development"' % (p12, key_path, cer_path))
        rc = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        log("openssl rc=%s err=%s" % (rc.returncode, rc.stderr[:200]))
        if rc.returncode == 0 and os.path.exists(p12):
            log("*** P12 EXPORTED -> %s (%d bytes) ***" % (p12, os.path.getsize(p12)))
            log("subject: %s" % subprocess.run(
                'openssl x509 -in "%s" -noout -subject -dates' % cer_path,
                shell=True, capture_output=True, text=True).stdout.strip())
            return 0
        log("p12 export failed")
        return 1

    log("no cert PEM in response -- dumping full response for inspection")
    log(json.dumps(resp, default=str)[:3000])
    return 1


if __name__ == "__main__":
    sys.exit(main())
