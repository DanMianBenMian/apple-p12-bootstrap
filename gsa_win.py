#!/usr/bin/env python3
"""gsa_win.py - GSA login with WINDOWS identity anisette (post 2026-10-12 Apple block).

Background (2026-10-12+): Apple rejects GSA init when anisette data comes from
Android CoreADI libs (-80045 "This action cannot be completed at this time"),
and answers Android client-info with 503 HTML. The bare GsService2 path 503s;
actions now live at /grandslam/GsService2/<action> (init/complete/apptokens).

Working combo: anisette data from a WINDOWS CoreADI server + matching
X-MMe-Client-Info ("<PC> <Windows;6.2(0,0);9200> <com.apple.AuthKit/1
(com.apple.iTunes/12.12.4.1)>") + UA "akd/1.0 CFNetwork/808.1.4".

Phases:
  provision   provision anisette from a Windows server, save win_state.json
  auth        init -> complete -> (hsc 409) send 2FA code
  submit <c>  submit code -> relogin -> apptokens -> apple_tokens.json
"""
import base64
import hashlib
import hmac
import json
import os
import sys
import time
import uuid

import plistlib as plist
import requests
import srp._pysrp as srp
import urllib3
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

urllib3.disable_warnings()
srp.rfc5054_enable()
srp.no_username_in_x()

HERE = os.path.dirname(os.path.abspath(__file__))
STATE = os.path.join(HERE, "win_state.json")
APPLE_ID = "mocswpkddhxa@aniimate.net"
PASSWORD = "Aa19841129."
APP_ID = "com.apple.gs.xcode.auth"
GS_BASE = "https://gsa.apple.com/grandslam/GsService2"
# Windows anisette servers (article: still working as of 2026-10-17)
SERVERS = [
    "https://ani.jkcoxson.com",
    "https://ani2.stikstore.app",
    "https://ani.sidestore.io",
    "https://ani.stikstore.app",
]


def log(*a):
    print("[win]", *a, flush=True)


def load_state():
    if os.path.exists(STATE):
        with open(STATE) as f:
            return json.load(f)
    return {}


def save_state(st):
    with open(STATE, "w") as f:
        json.dump(st, f, indent=1)
    log("state ->", STATE)


def now_iso():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def url_bag(s):
    r = s.get(GS_BASE + "/lookup", verify=False, timeout=15,
              headers={"User-Agent": "akd/1.0 CFNetwork/808.1.4",
                       "X-Mme-Client-Info": load_state().get(
                           "client_info", "<PC> <Windows;6.2(0,0);9200> <com.apple.AuthKit/1 (com.apple.iTunes/12.12.4.1)>")})
    r.raise_for_status()
    return dict(plist.loads(r.content)["urls"])


# ---------------- provisioning (Windows anisette server) ----------------

def provision():
    from websockets.sync.client import connect
    s = requests.Session()
    s.trust_env = False
    state = {}
    for base in SERVERS:
        try:
            r = s.get(base + "/v3/client_info", verify=False, timeout=10)
            r.raise_for_status()
            ci = r.json()
            client_info = ci["client_info"]
            user_agent = ci["user_agent"]
            log("server %s client_info: %s" % (base, client_info))
        except Exception as e:
            log("server %s client_info failed: %s" % (base, str(e)[:100]))
            continue
        try:
            device_id = str(uuid.uuid4()).upper()
            h = {
                "User-Agent": user_agent,
                "X-Apple-Baa-E": "-10000",
                "X-Apple-I-MD-LU": "0",
                "X-Mme-Device-Id": device_id,
                "X-Apple-Baa-Avail": "2",
                "X-Mme-Client-Info": client_info,
                "X-Apple-I-Client-Time": now_iso(),
                "Accept-Language": "en-US,en;q=0.9",
                "X-Apple-Client-App-Name": "akd",
                "Accept": "*/*",
                "Content-Type": "application/x-www-form-urlencoded",
                "X-Apple-Baa-UE": "AKAuthenticationError:-7066|com.apple.devicecheck.error.baa:-10000",
                "X-Apple-Host-Baa-E": "-7066",
            }
            bag = url_bag(s)
            r = s.post(bag["midStartProvisioning"], verify=False,
                       data=plist.dumps({"Header": {}, "Request": {}}),
                       headers=h, timeout=15)
            r.raise_for_status()
            spim = plist.loads(r.content)["Response"]["spim"]
            identifier = base64.b64encode(bytes(random_byte())).decode() if False else base64.b64encode(os.urandom(16)).decode()
            rinfo = adi_pb = None
            with connect(base.replace("https://", "wss://") + "/v3/provisioning_session") as ws:
                while True:
                    msg = json.loads(ws.recv())
                    result = msg.get("result")
                    if result == "GiveIdentifier":
                        ws.send(json.dumps({"identifier": identifier}))
                    elif result == "GiveStartProvisioningData":
                        ws.send(json.dumps({"spim": spim}))
                    elif result == "GiveEndProvisioningData":
                        cpim = msg["cpim"]
                        r2 = s.post(bag["midFinishProvisioning"], verify=False,
                                    data=plist.dumps({"Header": {}, "Request": {"cpim": cpim}}),
                                    headers=h, timeout=15)
                        r2.raise_for_status()
                        resp2 = plist.loads(r2.content)["Response"]
                        rinfo = resp2.get("X-Apple-I-MD-RINFO")
                        ws.send(json.dumps({"ptm": resp2["ptm"], "tk": resp2["tk"]}))
                    elif result == "ProvisioningSuccess":
                        adi_pb = msg["adi_pb"]
                        break
                    elif result == "Timeout":
                        raise RuntimeError("timeout")
            if not adi_pb:
                continue
            r3 = s.post(base + "/v3/get_headers", verify=False,
                        json={"adi_pb": adi_pb, "identifier": identifier}, timeout=15)
            r3.raise_for_status()
            j = r3.json()
            log("get_headers keys: %s" % sorted(j.keys()))
            state = {
                "server": base,
                "client_info": client_info,
                "user_agent": user_agent,
                "device_id": device_id,
                "identifier": identifier,
                "adi_pb": adi_pb,
                "rinfo": rinfo,
                "md": j.get("X-Apple-I-MD"),
                "md_m": j.get("X-Apple-I-MD-M"),
                "md_lu": j.get("X-Apple-I-MD-LU"),
                "extra": {k: v for k, v in j.items() if k not in ("X-Apple-I-MD", "X-Apple-I-MD-M")},
            }
            break
        except Exception as e:
            log("server %s provision failed: %s %s" % (base, type(e).__name__, str(e)[:120]))
            continue
    if not state:
        raise RuntimeError("all servers failed")
    save_state(state)
    log("provisioned: rinfo=%s md=%s..." % (state["rinfo"], (state["md"] or "")[:30]))
    return state


def random_byte():
    return os.urandom(16)


# ---------------- GSA ----------------

def make_cpd(st):
    return {
        "bootstrap": True, "icscrec": True, "pbe": False, "prkgen": True, "svct": "iCloud",
        "loc": "en_US", "X-Apple-Locale": "en_US",
        "X-Apple-I-MD": st["md"], "X-Apple-I-MD-M": st["md_m"],
        "X-Apple-I-MD-RINFO": str(st["rinfo"]),
        "X-Apple-I-MD-LU": st.get("md_lu") or base64.b64encode(b"0011223344").decode(),
        "X-Mme-Device-Id": st["device_id"],
        "X-Apple-I-SRL-NO": "C02XL0XYJGH5",
        "X-Apple-I-Client-Time": now_iso(),
        "X-Apple-I-TimeZone": "UTC",
    }


def gsa_headers(st):
    return {
        "Content-Type": "text/x-xml-plist",
        "Accept": "*/*",
        "X-Mme-Client-Info": st["client_info"],
        "User-Agent": st["user_agent"],
    }


def refresh_headers(s, st):
    """Re-fetch a FRESH X-Apple-I-MD (OTP) from the anisette server.

    GSA status 434 = "Anisette Resync Required" -> the X-Apple-I-MD one-time
    password expired (~30s TTL). provisioning() does several websocket+HTTP
    round trips, so by the time init is posted the OTP is often already stale.
    Fix: pull a new OTP immediately before each GSA call, and retry on 434.
    """
    try:
        r = s.post(st["server"] + "/v3/get_headers", verify=False,
                   json={"adi_pb": st["adi_pb"], "identifier": st["identifier"]},
                   timeout=15)
        r.raise_for_status()
        j = r.json()
        if not j.get("X-Apple-I-MD"):
            log("refresh_headers: no MD in response: %s" % sorted(j.keys()))
            return False
        st["md"] = j["X-Apple-I-MD"]
        st["md_m"] = j.get("X-Apple-I-MD-M", st["md_m"])
        if j.get("X-Apple-I-MD-RINFO"):
            st["rinfo"] = j["X-Apple-I-MD-RINFO"]
        st.setdefault("extra", {}).update(
            {k: v for k, v in j.items() if k not in ("X-Apple-I-MD", "X-Apple-I-MD-M")})
        save_state(st)
        log("refreshed MD: %s..." % st["md"][:28])
        return True
    except Exception as e:
        log("refresh_headers failed: %s %s" % (type(e).__name__, str(e)[:140]))
        return False


def srp_user():
    return srp.User(APPLE_ID, bytes(), hash_alg=srp.SHA256, ng_type=srp.NG_2048)


def encrypt_password(password, salt, iterations, protocol):
    p = hashlib.sha256(password.encode("utf-8")).digest()
    if protocol == "s2k_fo":
        p = p.hex().encode("utf-8")
    return hashlib.pbkdf2_hmac("sha256", p, salt, iterations, 32)


def do_init(s, st, tries=5):
    for attempt in range(tries):
        # OTP is ~30s TTL; always grab a fresh one right before the call.
        refresh_headers(s, st)
        usr = srp_user()
        _, A = usr.start_authentication()
        body = {"Header": {"Version": "1.0.1"},
                "Request": {"A2k": A, "cpd": make_cpd(st), "o": "init",
                            "ps": ["s2k", "s2k_fo"], "u": APPLE_ID}}
        r = s.post(GS_BASE + "/init", data=plist.dumps(body), headers=gsa_headers(st),
                   verify=False, timeout=20)
        log("init: HTTP %s len %d" % (r.status_code, len(r.content)))
        txt = r.text
        log("init resp:", txt[:900])
        try:
            resp = plist.loads(txt.encode())["Response"]
        except Exception as e:
            log("parse fail:", e)
            return None
        stt = resp.get("Status", {})
        log("init Status:", stt)
        # 434 = Anisette Resync Required (expired OTP) -> refresh + retry
        if stt.get("hsc") == 434:
            log("hsc 434 anisette resync; refresh+retry %d/%d" % (attempt + 1, tries))
            continue
        if "s" not in resp or "B" not in resp:
            return None
        st.update({
            "a": hex(usr.a),
            "salt": base64.b64encode(resp["s"]).decode(),
            "B": base64.b64encode(resp["B"]).decode(),
            "i": resp["i"], "sp": resp["sp"], "c": resp["c"],
        })
        save_state(st)
        log("init OK: sp=%s i=%s" % (resp["sp"], resp["i"]))
        return st
    log("init gave up after %d tries" % tries)
    return None


def do_complete(s, st, fresh=True):
    if fresh:
        st = do_init(s, st)
        if not st:
            return None
    usr = srp_user()
    usr.a = int(st["a"], 16)
    salt = base64.b64decode(st["salt"])
    B = base64.b64decode(st["B"])
    usr.p = encrypt_password(PASSWORD, salt, st["i"], st["sp"])
    M1 = usr.process_challenge(salt, B)
    if M1 is None:
        log("process_challenge failed")
        return None
    body = {"Header": {"Version": "1.0.1"},
            "Request": {"M1": M1, "c": st["c"], "cpd": make_cpd(st),
                        "o": "complete", "u": APPLE_ID}}
    r = s.post(GS_BASE + "/complete", data=plist.dumps(body), headers=gsa_headers(st),
               verify=False, timeout=20)
    log("complete: HTTP %s len %d" % (r.status_code, len(r.content)))
    txt = r.text
    log("complete resp:", txt[:1200])
    try:
        resp = plist.loads(txt.encode())["Response"]
    except Exception as e:
        log("parse fail:", e)
        return None
    status = resp.get("Status", {})
    log("complete Status:", status)
    if "spd" not in resp:
        return None
    if "M2" in resp:
        log("M2 verify:", usr.verify_session(resp["M2"]))
    K = usr.get_session_key()
    ek = hmac.new(K, b"extra data key:", hashlib.sha256).digest()
    ei = hmac.new(K, b"extra data iv:", hashlib.sha256).digest()[:16]
    dec = Cipher(algorithms.AES(ek), modes.CBC(ei)).decryptor()
    data = dec.update(resp["spd"]) + dec.finalize()
    spd = plist.loads(padding.PKCS7(128).unpadder().update(data) +
                      padding.PKCS7(128).unpadder().finalize(), fmt=plist.FMT_XML)
    log("spd keys:", sorted(spd.keys()))
    out = {"hsc": status.get("hsc", 0), "au": status.get("au", ""),
           "adsid": spd.get("adsid"), "idmsToken": spd.get("GsIdmsToken"),
           "sk_b64": base64.b64encode(spd["sk"]).decode() if "sk" in spd else None,
           "spd_c_b64": base64.b64encode(spd["c"]).decode() if "c" in spd else None}
    log("hsc=%s au=%s adsid=%s" % (out["hsc"], out["au"], out["adsid"]))
    st.update({k: v for k, v in out.items() if v is not None})
    save_state(st)
    return out


def do_sendcode(s, st):
    identity = base64.b64encode(("%s:%s" % (st["adsid"], st["idmsToken"])).encode()).decode()
    st["identityToken"] = identity
    save_state(st)
    h = dict(gsa_headers(st))
    h["X-Apple-Identity-Token"] = identity
    h["X-Apple-I-MD"] = st["md"]
    h["X-Apple-I-MD-M"] = st["md_m"]
    h["X-Apple-I-MD-RINFO"] = str(st["rinfo"])
    h["X-Apple-I-Client-Time"] = now_iso()
    h["X-Apple-Locale"] = "en_US"
    h["X-Apple-I-TimeZone"] = "UTC"
    r = s.get("https://gsa.apple.com/auth/verify/trusteddevice", headers=h,
              verify=False, timeout=20)
    log("sendcode: HTTP %s resp: %s" % (r.status_code, r.text[:300]))
    return r.status_code == 200


def do_submitcode(s, st, code):
    h = dict(gsa_headers(st))
    h["X-Apple-Identity-Token"] = st["identityToken"]
    h["security-code"] = code
    h["X-Apple-I-MD"] = st["md"]
    h["X-Apple-I-MD-M"] = st["md_m"]
    h["X-Apple-I-MD-RINFO"] = str(st["rinfo"])
    h["X-Apple-I-Client-Time"] = now_iso()
    h["X-Apple-Locale"] = "en_US"
    h["X-Apple-I-TimeZone"] = "UTC"
    r = s.get(GS_BASE + "/validate", headers=h, verify=False, timeout=20)
    log("validateCode: HTTP %s resp: %s" % (r.status_code, r.text[:300]))
    try:
        v = plist.loads(r.text.encode())
        log("validateCode ec=%s em=%s" % (v.get("ec"), v.get("em")))
        return v.get("ec") == 0
    except Exception as e:
        log("parse fail:", e)
        return False


def do_apptokens(s, st):
    sk = base64.b64decode(st["sk_b64"])
    c = base64.b64decode(st["spd_c_b64"])
    checksum = hmac.new(sk, b"apptokens" + st["adsid"].encode() + APP_ID.encode(),
                        hashlib.sha256).digest()
    body = {"Header": {"Version": "1.0.1"},
            "Request": {"u": st["adsid"], "app": [APP_ID], "c": c,
                        "t": st["idmsToken"], "checksum": checksum,
                        "cpd": make_cpd(st), "o": "apptokens"}}
    r = s.post(GS_BASE + "/apptokens", data=plist.dumps(body), headers=gsa_headers(st),
               verify=False, timeout=20)
    log("apptokens: HTTP %s len %d" % (r.status_code, len(r.content)))
    log("apptokens resp:", r.text[:600])
    try:
        resp = plist.loads(r.text.encode())["Response"]
    except Exception as e:
        log("parse fail:", e)
        return False
    stt = resp.get("Status", {})
    log("apptokens Status:", stt)
    if "et" not in resp:
        return False
    et = resp["et"]
    if et[:3] != b"XYZ":
        log("et header mismatch")
        return False
    iv, ct = et[3:19], et[19:]
    token_xml = AESGCM(sk).decrypt(iv, ct, b"XYZ")
    tok = plist.loads(token_xml, fmt=plist.FMT_XML)
    token = tok["t"][APP_ID]["token"]
    log("*** TOKEN ACQUIRED (len %d) ***" % len(token))
    final = {"apple_id": APPLE_ID, "adsid": st["adsid"],
             "idmsToken": st["idmsToken"], "appId": APP_ID, "token": token,
             "sk_b64": st["sk_b64"], "spd_c_b64": st["spd_c_b64"],
             "client_info": st["client_info"], "user_agent": st["user_agent"],
             "device_id": st["device_id"], "md": st["md"], "md_m": st["md_m"],
             "rinfo": st["rinfo"]}
    with open(os.path.join(HERE, "apple_tokens.json"), "w") as f:
        json.dump(final, f, indent=1)
    log("tokens -> apple_tokens.json")
    return True


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "auth"
    s = requests.Session()
    s.trust_env = False
    st = load_state()
    if cmd == "provision":
        provision()
        return 0
    if cmd == "freshauth":
        # provision + init + complete back-to-back (anisette MD is time-sensitive)
        provision()
        st = load_state()
        out = do_complete(s, st, fresh=True)
        if not out:
            return 1
        if out["hsc"] == 409 and out.get("au") not in ("repair", None, ""):
            log("2FA required (au=%s)" % out["au"])
            if do_sendcode(s, st):
                log("CODE SENT. Run: python gsa_win.py submit <code>")
            return 2
        if out["hsc"] == 409:
            log("au=repair ignored (sk+c present)")
        return 0 if do_apptokens(s, st) else 1
    if not st:
        log("no state; run provision first")
        return 1
    if cmd == "auth":
        out = do_complete(s, st, fresh=True)
        if not out:
            return 1
        if out["hsc"] == 409 and out.get("au") not in ("repair", None, ""):
            log("2FA required (au=%s)" % out["au"])
            if do_sendcode(s, st):
                log("CODE SENT. Run: python gsa_win.py submit <code>")
            return 2
        if out["hsc"] == 409:
            log("au=repair ignored (sk+c present)")
        return 0 if do_apptokens(s, st) else 1
    if cmd == "submit":
        if len(sys.argv) < 3:
            log("usage: gsa_win.py submit <code>")
            return 1
        if not do_submitcode(s, st, sys.argv[2].strip()):
            return 1
        out = do_complete(s, st, fresh=True)
        if not out:
            return 1
        log("relogin hsc=%s" % out["hsc"])
        return 0 if do_apptokens(s, st) else 1
    if cmd == "apptokens":
        return 0 if do_apptokens(s, st) else 1
    log("unknown cmd")
    return 1


if __name__ == "__main__":
    sys.exit(main())
