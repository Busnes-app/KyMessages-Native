#!/usr/bin/env python3
"""A KyMessages bot as an end-to-end encrypted device (E4 of the e2ee design).

The bot's keys live only in its state file, never on the server. Its owner vouches for the
device in KyMessages ("Your bots") after comparing the code `init` prints. The bot trusts what
a person's browser trusts, checked the same way: a member's master key is pinned on first sight
(self-bound, ML-DSA-65 + Ed25519), and only devices that key cross-signed and lists on its newest
signed device list get room keys or are believed; a bot's devices only through its owner's signed
list. Lists only move forward, so the server cannot add a device or bring a removed one back.

    KYMESSAGES_SERVER_URL=https://chat.example.com KYMESSAGES_ACCESS_TOKEN=kybot_... kybot.py init
    kybot.py sync                      # read room keys sent to this device
    kybot.py read ROOM_ID [--limit N]  # decrypted messages, one JSON object per line
    kybot.py send ROOM_ID TEXT [--file PATH]
    kybot.py download ROOM_ID MESSAGE_ID ATTACHMENT_ID OUT
    kybot.py decrypt < message.json    # one message (a WebSocket frame's message)

Requires vodozemac==0.10.0 and cryptography>=50 (requirements.txt).
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

import vodozemac as vz
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- Formats (internal/e2eeid, web/src/crypto): never change one here alone ---

ALG = "mldsa65+ed25519"
TAG = ALG.encode() + b"\0"
MLDSA65_PUB, MLDSA65_SIG = 1952, 3309
DOMAIN_MASTER = "kymessages.master.v1"
DOMAIN_DEVICE = "kymessages.device.v2"
DOMAIN_DEVICE_LIST = "kymessages.device-list.v1"
DOMAIN_BOT_DEVICES = "kymessages.bot-devices.v1"
ROOM_KEY_TYPE = "kymessages.room_key.v1"
ROTATE_AFTER_MESSAGES = 100
ROTATE_AFTER_S = 7 * 24 * 3600
OTK_TARGET = 50
CHUNK = 64 << 10
ATT_LABEL = b"kymessages.attachment.v1"
MAX_CIPHERTEXT = 100 << 20


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode().rstrip("=")


def unb64(s: str, length: int | None = None) -> bytes:
    """Canonical unpadded base64 only: one value has one spelling."""
    if not isinstance(s, str) or not s or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" for c in s):
        raise ValueError("not base64")
    b = base64.b64decode(s + "=" * (-len(s) % 4))
    if b64(b) != s or (length is not None and len(b) != length):
        raise ValueError("not canonical base64")
    return b


def fields(*fs: bytes) -> bytes:
    return b"".join(struct.pack(">I", len(f)) + f for f in fs)


def phash(*args: str) -> str:
    return hashlib.sha256(fields(*(a.encode() for a in args))).hexdigest()


def hybrid_verify(pub_b64: str, label: str, msg: bytes, sig_b64: str) -> bool:
    """ky-primitives hybridsig: both ML-DSA-65 and Ed25519 must verify over SHA-256(label 0 msg)."""
    try:
        pub, sig = unb64(pub_b64), unb64(sig_b64)
    except ValueError:
        return False
    if not pub.startswith(TAG) or len(pub) != len(TAG) + MLDSA65_PUB + 32:
        return False
    if not sig.startswith(TAG) or len(sig) != len(TAG) + MLDSA65_SIG + 64:
        return False
    pub, sig = pub[len(TAG):], sig[len(TAG):]
    digest = hashlib.sha256(label.encode() + b"\0" + msg).digest()
    try:
        mldsa.MLDSA65PublicKey.from_public_bytes(pub[:MLDSA65_PUB]).verify(sig[:MLDSA65_SIG], digest)
        ed25519.Ed25519PublicKey.from_public_bytes(pub[MLDSA65_PUB:]).verify(sig[MLDSA65_SIG:], digest)
    except (InvalidSignature, ValueError):
        return False
    return True


def fingerprint(pub_b64: str) -> str:
    return hashlib.sha256(b"kymessages.master-fingerprint.v1\0" + unb64(pub_b64)).hexdigest()


def master_self_msg(tenant: str, user: str, pub_b64: str) -> bytes:
    return fields(ALG.encode(), tenant.encode(), user.encode(), unb64(pub_b64))


def device_msg(tenant: str, user: str, device: str, curve: str, ed: str) -> bytes:
    return fields(*(v.encode() for v in (ALG, tenant, user, device, curve, ed)))


def device_list_msg(tenant: str, user: str, version: int, epoch: int, ids: list[str]) -> bytes:
    if ids != sorted(set(ids)):
        raise ValueError("device list must be sorted and distinct")
    return fields(*(v.encode() for v in (ALG, tenant, user, str(version), str(epoch), *ids)))


def bot_devices_msg(tenant: str, owner: str, version: int, bot: str, epoch: int, devices: list[dict]) -> bytes:
    ids = [d["device_id"] for d in devices]
    if ids != sorted(set(ids)):
        raise ValueError("bot devices must be sorted and distinct")
    flat = [v for d in devices for v in (d["device_id"], d["curve25519"], d["ed25519"])]
    return fields(*(v.encode() for v in (ALG, tenant, owner, str(version), bot, str(epoch), *flat)))


def device_code(bot: str, device: str, curve: str, ed: str) -> str:
    """What the owner compares before vouching (web/src/crypto/engine.ts botDeviceCode)."""
    h = phash("kymessages.bot-device-code.v1", bot, device, curve, ed)[:20]
    return "-".join(h[i:i + 4] for i in range(0, 20, 4))


def device_signed(user: str, device: str, curve: str, ed: str) -> bytes:
    return f"kymessages.device.v1\n{user}\n{device}\n{curve}\n{ed}".encode()


def otk_signed(user: str, device: str, key_id: str, key: str) -> bytes:
    return f"kymessages.otk.v1\n{user}\n{device}\n{key_id}\n{key}".encode()


def ed_verify(ed_b64: str, msg: bytes, sig_b64: str) -> bool:
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(unb64(ed_b64, 32)).verify(unb64(sig_b64, 64), msg)
    except (InvalidSignature, ValueError):
        return False
    return True


def valid_key(v: object) -> bool:
    try:
        unb64(v, 32)  # type: ignore[arg-type]
    except (ValueError, TypeError):
        return False
    return True


# --- Attachments: A256GCM-STREAM v1 (web/src/crypto/attachments.ts) ---

def _chunk_params(prefix: bytes, kind: str, index: int, final: bool) -> tuple[bytes, bytes]:
    flag = b"\1" if final else b"\0"
    return prefix + struct.pack(">I", index) + flag, ATT_LABEL + b"\0" + kind.encode() + struct.pack(">I", index) + flag


def encrypt_blob(data: bytes, kind: str = "file", chunk: int = CHUNK, key: bytes | None = None, prefix: bytes | None = None) -> tuple[bytes, dict]:
    key = key or secrets.token_bytes(32)
    prefix = prefix or secrets.token_bytes(7)
    aes = AESGCM(key)
    pieces = [data[i:i + chunk] for i in range(0, len(data), chunk)] or [b""]
    out = b"".join(aes.encrypt(*_order(prefix, kind, i, i == len(pieces) - 1, p)) for i, p in enumerate(pieces))
    return out, {"v": 1, "alg": "A256GCM-STREAM", "key": b64(key), "nonce_prefix": b64(prefix), "chunk_size": chunk,
                 "sha256": hashlib.sha256(out).hexdigest(), "ciphertext_size": len(out), "size": len(data)}


def _order(prefix: bytes, kind: str, i: int, final: bool, plain: bytes) -> tuple[bytes, bytes, bytes]:
    nonce, aad = _chunk_params(prefix, kind, i, final)
    return nonce, plain, aad


def decrypt_blob(ct: bytes, d: dict, kind: str = "file") -> bytes:
    """Checks length and SHA-256 of the whole ciphertext before opening any chunk."""
    chunk = d["chunk_size"]
    if d.get("v") != 1 or d.get("alg") != "A256GCM-STREAM" or not 4 << 10 <= chunk <= 4 << 20:
        raise ValueError("unknown attachment format")
    if len(ct) != d["ciphertext_size"] or hashlib.sha256(ct).hexdigest() != d["sha256"]:
        raise ValueError("attachment ciphertext does not match its descriptor")
    aes, prefix, full = AESGCM(unb64(d["key"], 32)), unb64(d["nonce_prefix"], 7), chunk + 16
    n = max(1, -(-len(ct) // full))
    last = len(ct) - (n - 1) * full
    if last < 16 or (n > 1 and last == 16) or len(ct) - 16 * n != d["size"]:
        raise ValueError("attachment ciphertext has the wrong length")
    out = []
    for i in range(n):
        nonce, aad = _chunk_params(prefix, kind, i, i == n - 1)
        out.append(aes.decrypt(nonce, ct[i * full:(i + 1) * full], aad))
    return b"".join(out)


# --- Local state: the bot's keys, pins and sessions. Keep it private (0600). ---

class State:
    def __init__(self, path: str):
        self.path = path
        try:
            with open(path, encoding="utf-8") as f:
                self.d = json.load(f)
        except FileNotFoundError:
            self.d = {}

    def save(self) -> None:
        tmp = f"{self.path}.{os.getpid()}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(self.d, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.path)

    def __getitem__(self, k):
        return self.d.setdefault(k, {})

    @property
    def key(self) -> bytes:
        return unb64(self.d["pickle_key"], 32)


class Server:
    def __init__(self, url: str, token: str):
        u = urllib.parse.urlparse(url)
        if u.scheme != "https" and u.hostname not in ("127.0.0.1", "localhost", "::1"):
            raise SystemExit("KYMESSAGES_SERVER_URL must be https (or loopback)")
        self.url, self.token = url.rstrip("/"), token

    def call(self, method: str, path: str, body=None, raw: bytes | None = None, ctype: str = "application/json"):
        data = raw if raw is not None else (None if body is None else json.dumps(body).encode())
        req = urllib.request.Request(self.url + path, data=data, method=method,
                                     headers={"Authorization": "Bearer " + self.token, "Content-Type": ctype})
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                out = r.read()
        except urllib.error.HTTPError as e:
            raise SystemExit(f"{method} {path}: HTTP {e.code} {e.read()[:300].decode(errors='replace')}")
        return out if raw is not None and method == "GET" else (json.loads(out) if out else None)

    def get_bytes(self, path: str, limit: int) -> bytes:
        req = urllib.request.Request(self.url + path, headers={"Authorization": "Bearer " + self.token})
        with urllib.request.urlopen(req, timeout=120) as r:
            out = r.read(limit + 1)
        if len(out) > limit:
            raise ValueError("download larger than its descriptor")
        return out


class Bot:
    def __init__(self, server: Server, state: State, user_id: str | None = None):
        self.s, self.st = server, state
        self.user_id = user_id or state.d.get("user_id") or server.call("GET", "/api/auth/me")["user"]["id"]

    # Device setup

    def account(self) -> vz.Account:
        return vz.Account.from_pickle(self.st.d["account"], self.st.key)

    def keep(self, acct: vz.Account) -> None:
        self.st.d["account"] = acct.pickle(self.st.key)

    @property
    def device_id(self) -> str:
        return self.st.d["device_id"]

    def init(self) -> dict:
        if "account" not in self.st.d:
            acct = vz.Account()
            self.st.d.update(pickle_key=b64(secrets.token_bytes(32)), user_id=self.user_id,
                             device_id="BOT" + secrets.token_hex(8).upper())
            self.keep(acct)
            self.st.save()
        acct = self.account()
        curve, ed = acct.curve25519_key.to_base64(), acct.ed25519_key.to_base64()
        keys = {"curve25519": curve, "ed25519": ed, "signature": acct.sign(device_signed(self.user_id, self.device_id, curve, ed)).to_base64()}
        self.upload(acct, keys)
        return {"user_id": self.user_id, "device_id": self.device_id, "code": device_code(self.user_id, self.device_id, curve, ed)}

    def upload(self, acct: vz.Account, device_keys: dict | None = None, count: int | None = None) -> None:
        need = OTK_TARGET if count is None else max(0, OTK_TARGET - count)
        if need:
            acct.generate_one_time_keys(need)
        otks = [{"key_id": k, "key": v.to_base64(), "signature": acct.sign(otk_signed(self.user_id, self.device_id, k, v.to_base64())).to_base64()}
                for k, v in acct.one_time_keys.items()]
        body = {"device_id": self.device_id, "one_time_keys": otks}
        if device_keys:
            body["device_keys"] = device_keys
        self.s.call("POST", "/api/v1/keys/upload", body)
        acct.mark_keys_as_published()
        self.keep(acct)
        self.st.save()

    # Trust: who may have this bot's room keys, and whose room keys it believes

    def observe(self, key: str, epoch: int | None, digest: str | None) -> bool:
        """Lists only move forward: older, forked at one epoch, or missing once seen is refused."""
        marks = self.st["marks"]
        seen = marks.get(key)
        if epoch is None:
            return seen is None
        if seen and seen["epoch"] > epoch:
            return False
        if seen and seen["epoch"] == epoch:
            if seen["digest"] != digest:
                seen["fork"] = True
            return not seen.get("fork")
        marks[key] = {"epoch": epoch, "digest": digest}
        return True

    def trusted_master(self, user: str, rec, tenant: str) -> tuple[str, set[str]] | None:
        """user's pinned, self-bound master key and the devices on its newest signed list."""
        if not isinstance(rec, dict) or not isinstance(rec.get("version"), int) or rec["version"] < 1:
            return None
        key, ver = rec.get("master_key"), rec["version"]
        if not hybrid_verify(key, DOMAIN_MASTER, master_self_msg(tenant, user, key), rec.get("self_signature", "")):
            return None
        fp = fingerprint(key)
        pins = self.st["pins"]
        pin = pins.get(f"{tenant}:{user}")
        if f"{tenant}:{user}" in self.st["changed"]:
            # A change waits for `accept`, whichever key the server shows next (the old one too).
            self.st["changed"][f"{tenant}:{user}"] = fp if fp != pin else self.st["changed"][f"{tenant}:{user}"]
            return None
        if pin is None:
            pins[f"{tenant}:{user}"] = fp  # first sight
        elif pin != fp:
            print(f"warning: {user}'s encryption identity changed; nothing is shared with them until `kybot.py accept {user}`", file=sys.stderr)
            self.st["changed"][f"{tenant}:{user}"] = fp
            return None
        dl = rec.get("device_list")
        ids: list[str] = []
        if dl is not None:
            ids = dl.get("device_ids") if isinstance(dl, dict) else None
            if not isinstance(ids, list) or not all(isinstance(i, str) for i in ids) or not isinstance(dl.get("epoch"), int):
                return None
            try:
                msg = device_list_msg(tenant, user, ver, dl["epoch"], ids)
            except ValueError:
                return None
            if not hybrid_verify(key, DOMAIN_DEVICE_LIST, msg, dl.get("signature", "")):
                return None
        ok = self.observe(f"dlh:{tenant}:{user}:{fp}:{ver}", dl and dl["epoch"], dl and phash("kymessages.device-list", *ids))
        return (key, set(ids)) if ok and dl else None

    def trusted_bot(self, bot: str, rec, q: dict, tenant: str) -> dict[str, dict] | None:
        if not isinstance(rec, dict) or not isinstance(rec.get("owner_id"), str) or not isinstance(rec.get("devices"), list):
            return None
        # A bot's owner is pinned on first sight: no other member can vouch for it later.
        owners = self.st["bot_owners"]
        if owners.setdefault(f"{tenant}:{bot}", rec["owner_id"]) != rec["owner_id"]:
            print(f"warning: the server names another owner for {bot}; it gets nothing", file=sys.stderr)
            return None
        owner = self.trusted_master(rec["owner_id"], q.get("master_keys", {}).get(rec["owner_id"]), tenant)
        if not owner or not isinstance(rec.get("version"), int) or not isinstance(rec.get("epoch"), int):
            return None
        devs = rec["devices"]
        if not all(isinstance(d, dict) and valid_key(d.get("curve25519")) and valid_key(d.get("ed25519")) and isinstance(d.get("device_id"), str) for d in devs):
            return None
        try:
            msg = bot_devices_msg(tenant, rec["owner_id"], rec["version"], bot, rec["epoch"], devs)
        except ValueError:
            return None
        valid = hybrid_verify(owner[0], DOMAIN_BOT_DEVICES, msg, rec.get("signature", ""))
        flat = [v for d in devs for v in (d["device_id"], d["curve25519"], d["ed25519"])]
        if not valid or not self.observe(f"blh:{tenant}:{bot}:{rec['owner_id']}:{fingerprint(owner[0])}", rec["epoch"], phash("kymessages.bot-devices", *flat)):
            return None
        return {d["device_id"]: d for d in devs}

    def check_device(self, user: str, d) -> dict | None:
        """d's self-signature verifies and its keys match what this bot saw before (never re-pinned)."""
        if not isinstance(d, dict) or not all(isinstance(d.get(k), str) for k in ("device_id", "curve25519", "ed25519", "signature")):
            return None
        if not ed_verify(d["ed25519"], device_signed(user, d["device_id"], d["curve25519"], d["ed25519"]), d["signature"]):
            return None
        pins = self.st["device_pins"]
        k = f"{user}\n{d['device_id']}"
        if k in pins and pins[k] != [d["curve25519"], d["ed25519"]]:
            return None
        pins[k] = [d["curve25519"], d["ed25519"]]
        return {"user_id": user, "device_id": d["device_id"], "curve25519": d["curve25519"], "ed25519": d["ed25519"]}

    def trusted_devices(self, users: list[str]) -> list[dict]:
        out = []
        for i in range(0, len(users), 100):
            batch = users[i:i + 100]
            q = self.s.call("POST", "/api/v1/keys/query", {"user_ids": batch})
            tenant = q.get("tenant_id")
            # The org is fixed at first contact: keys from another org are never this bot's peers.
            if not isinstance(tenant, str) or self.st.d.setdefault("tenant_id", tenant) != tenant:
                raise SystemExit("the key server answered for another organization; refusing")
            for u in batch:
                if u.startswith("bot_"):
                    vouched = self.trusted_bot(u, (q.get("bot_devices") or {}).get(u), q, tenant)
                    if vouched is None:
                        continue
                    trust = lambda d, v=vouched: d["device_id"] in v and [v[d["device_id"]]["curve25519"], v[d["device_id"]]["ed25519"]] == [d["curve25519"], d["ed25519"]]
                else:
                    m = self.trusted_master(u, q.get("master_keys", {}).get(u), tenant)
                    if m is None:
                        continue
                    trust = lambda d, m=m, u=u: d["device_id"] in m[1] and hybrid_verify(m[0], DOMAIN_DEVICE, device_msg(tenant, u, d["device_id"], d["curve25519"], d["ed25519"]), d.get("master_signature", ""))
                for d in q.get("devices", {}).get(u, []):
                    if u == self.user_id and isinstance(d, dict) and d.get("device_id") == self.device_id:
                        continue
                    t = self.check_device(u, d)
                    if t and trust(d):
                        out.append(t)
        self.st.save()
        return out

    # Mailbox: room keys over Olm

    def olm_decrypt(self, curve: str, typ: int, body: str) -> bytes:
        sessions = self.st["olm"].setdefault(curve, [])
        msg = vz.AnyOlmMessage.from_parts(typ, unb64(body))
        for i, p in enumerate(sessions):
            s = vz.Session.from_pickle(p, self.st.key)
            try:
                plain = s.decrypt(msg)
            except Exception:
                continue
            sessions[i] = s.pickle(self.st.key)
            return plain
        if typ != 0:
            raise ValueError("no Olm session for this message")
        acct = self.account()
        s, plain = acct.create_inbound_session(vz.Curve25519PublicKey.from_base64(curve), msg.to_pre_key())
        self.keep(acct)
        sessions.append(s.pickle(self.st.key))
        return plain

    def sync(self) -> list[str]:
        got: list[str] = []
        while True:
            page = self.s.call("GET", "/api/v1/to-device?device_id=" + urllib.parse.quote(self.device_id))["messages"]
            if not page:
                break
            senders = sorted({m.get("sender_user_id") for m in page if isinstance(m.get("sender_user_id"), str)})
            trusted = {(t["user_id"], t["device_id"], t["curve25519"]) for t in self.trusted_devices(senders)}
            for m in page:
                try:
                    sid = self.room_key(m, trusted)
                    if sid:
                        got.append(sid)
                except Exception as e:  # a refused or unreadable mail is dropped, as the browser does
                    print(f"refused mail {m.get('id')}: {e}", file=sys.stderr)
            self.st.save()  # ratchets and keys before the ack
            self.s.call("POST", "/api/v1/to-device/ack", {"device_id": self.device_id, "ids": [m["id"] for m in page]})
        count = self.s.call("POST", "/api/v1/keys/upload", {"device_id": self.device_id, "one_time_keys": []})
        if count.get("one_time_key_count", OTK_TARGET) < OTK_TARGET // 2:
            self.upload(self.account(), count=count["one_time_key_count"])
        return got

    def room_key(self, m: dict, trusted: set) -> str | None:
        if m.get("type") != ROOM_KEY_TYPE:
            raise ValueError("unknown mail type")
        c = json.loads(m["content"])
        sk = m.get("sender_keys") or {}
        sender = self.check_device(m["sender_user_id"], sk) if sk.get("device_id") == m.get("sender_device_id") else None
        if not sender or c.get("algorithm") != "olm.v1" or c.get("sender_key") != sender["curve25519"] or c.get("type") not in (0, 1):
            raise ValueError("mail from an unverified device")
        p = json.loads(self.olm_decrypt(sender["curve25519"], c["type"], c["body"]))
        if (sender["user_id"], sender["device_id"], sender["curve25519"]) not in trusted:
            raise ValueError("room key from a device nobody vouches for")
        acct = self.account()
        me = (self.user_id, self.device_id, acct.ed25519_key.to_base64())
        if p.get("type") != ROOM_KEY_TYPE or (p.get("sender_user_id"), p.get("sender_device_id"), p.get("sender_ed25519")) != (sender["user_id"], sender["device_id"], sender["ed25519"]) \
                or (p.get("recipient_user_id"), p.get("recipient_device_id"), p.get("recipient_ed25519")) != me:
            raise ValueError("room key addressed elsewhere")
        k = p["content"]
        if k.get("device_id") != sender["device_id"] or not isinstance(k.get("room_id"), str):
            raise ValueError("malformed room key")
        ig = vz.InboundGroupSession(vz.SessionKey(k["session_key"]))
        if ig.session_id != k["session_id"]:
            raise ValueError("room key does not match its session")
        slot = f"{sender['curve25519']}\n{k['session_id']}"
        known = self.st["inbound"].get(slot)
        if known and (known["room_id"], known["user"], known["device"]) != (k["room_id"], sender["user_id"], sender["device_id"]):
            raise ValueError("a session is bound to its first sender and room")
        if not known or ig.first_known_index < known["first_index"]:
            self.st["inbound"][slot] = {"pickle": ig.pickle(self.st.key), "room_id": k["room_id"], "user": sender["user_id"],
                                       "device": sender["device_id"], "first_index": ig.first_known_index}
        return k["session_id"]

    # Messages

    def open(self, m: dict) -> dict:
        """One stored message, decrypted and checked as the browser checks it."""
        base = {"id": m.get("id"), "room_id": m.get("room_id"), "sender_id": m.get("sender_id")}
        if m.get("encoding") != "e2ee_room_v1":
            return {**base, "encrypted": False, "body": m.get("body", "")}
        try:
            env = json.loads(m["body"])
            rec = self.st["inbound"].get(f"{env['sender_key']}\n{env['session_id']}")
        except (KeyError, ValueError, TypeError):
            return {**base, "error": "damaged"}
        if not rec:
            return {**base, "error": "waiting for this message's key (run sync)"}
        if (rec["user"], rec["device"], rec["room_id"]) != (m.get("sender_id"), env.get("device_id"), m.get("room_id")):
            return {**base, "error": "this message did not come from the device it names, or belongs to another room"}
        ig = vz.InboundGroupSession.from_pickle(rec["pickle"], self.st.key)
        try:
            dec = ig.decrypt(vz.MegolmMessage.from_base64(env["ciphertext"]))
        except Exception:
            return {**base, "error": "could not be decrypted"}
        try:
            inner = json.loads(dec.plaintext)
            if not isinstance(inner, dict) or not isinstance(inner.get("body", ""), str):
                raise ValueError
        except ValueError:
            return {**base, "error": "damaged"}
        if inner.get("room_id") != m.get("room_id") or (inner.get("type") == "edit" and inner.get("message_id") != m.get("id")):
            return {**base, "error": "encrypted for another room or message"}
        seen = self.st["seen"]
        slot = f"{env['sender_key']}\n{env['session_id']}\n{dec.message_index}"
        if seen.setdefault(slot, m.get("id")) != m.get("id"):
            return {**base, "error": "a replay of another message"}
        out = {**base, "encrypted": True, "type": inner.get("type"), "body": inner.get("body", "")}
        named = {a.get("id") for a in m.get("attachments") or []}
        files = [f for f in inner.get("files") or [] if isinstance(f, dict)]
        if files:
            out["files"] = [{"attachment_id": f.get("attachment_id"), "name": f.get("name"), "mime_type": f.get("mime_type"),
                             "size": f.get("size"), "available": f.get("attachment_id") in named} for f in files]
        return out

    def read(self, room: str, limit: int) -> list[dict]:
        page = self.s.call("GET", f"/api/v1/rooms/{urllib.parse.quote(room)}/messages?limit={limit}")
        out = [self.open(m) for m in page.get("messages", [])]
        self.st.save()
        return out

    def outbound(self, room: str, members: list[str], targets: list[dict]) -> vz.GroupSession:
        out = self.st["outbound"].get(room)
        if out:
            g = vz.GroupSession.from_pickle(out["pickle"], self.st.key)
            current = {f"{t['user_id']}\n{t['device_id']}": t["curve25519"] for t in targets}
            gone = any(k.split("\n")[0] not in members or current.get(k) != v for k, v in out["shared"].items())
            if not gone and g.message_index < ROTATE_AFTER_MESSAGES and time.time() - out["created"] < ROTATE_AFTER_S:
                return g
        g = vz.GroupSession()
        self.st["outbound"][room] = {"pickle": g.pickle(self.st.key), "created": time.time(), "shared": {}}
        # This bot reads its own messages too.
        own = vz.InboundGroupSession(g.session_key)
        self.st["inbound"][f"{self.account().curve25519_key.to_base64()}\n{g.session_id}"] = {
            "pickle": own.pickle(self.st.key), "room_id": room, "user": self.user_id, "device": self.device_id, "first_index": own.first_known_index}
        return g

    def share(self, room: str, g: vz.GroupSession, targets: list[dict]) -> None:
        out = self.st["outbound"][room]
        todo = [t for t in targets if out["shared"].get(f"{t['user_id']}\n{t['device_id']}") != t["curve25519"]]
        missing = [t for t in todo if not self.st["olm"].get(t["curve25519"])]
        if missing:
            byd = {(t["user_id"], t["device_id"]): t for t in missing}
            acct = self.account()
            for c in self.s.call("POST", "/api/v1/keys/claim", {"devices": [{"user_id": t["user_id"], "device_id": t["device_id"]} for t in missing]})["keys"]:
                t = byd.get((c.get("user_id"), c.get("device_id")))
                if t and ed_verify(t["ed25519"], otk_signed(t["user_id"], t["device_id"], c["key_id"], c["key"]), c["signature"]):
                    s = acct.create_outbound_session(vz.Curve25519PublicKey.from_base64(t["curve25519"]), vz.Curve25519PublicKey.from_base64(c["key"]))
                    self.st["olm"].setdefault(t["curve25519"], []).append(s.pickle(self.st.key))
        acct = self.account()
        content = {"room_id": room, "session_id": g.session_id, "session_key": g.session_key.to_base64(), "device_id": self.device_id}
        msgs = []
        for t in todo:
            pickles = self.st["olm"].get(t["curve25519"])
            if not pickles:
                continue  # no one-time key left: it gets the key next time
            s = vz.Session.from_pickle(pickles[-1], self.st.key)
            payload = {"type": ROOM_KEY_TYPE, "sender_user_id": self.user_id, "sender_device_id": self.device_id, "sender_ed25519": acct.ed25519_key.to_base64(),
                       "recipient_user_id": t["user_id"], "recipient_device_id": t["device_id"], "recipient_ed25519": t["ed25519"], "content": content}
            typ, ct = s.encrypt(json.dumps(payload).encode()).to_parts()
            pickles[-1] = s.pickle(self.st.key)
            msgs.append(({"user_id": t["user_id"], "device_id": t["device_id"], "type": ROOM_KEY_TYPE,
                          "content": json.dumps({"algorithm": "olm.v1", "sender_key": acct.curve25519_key.to_base64(), "type": typ, "body": b64(ct)})}, t))
        self.st.save()  # ratchets before anything leaves
        for i in range(0, len(msgs), 100):
            batch = msgs[i:i + 100]
            self.s.call("PUT", "/api/v1/to-device", {"device_id": self.device_id, "messages": [m for m, _ in batch]})
            # Shared only once delivered: a failed send is sent again next time.
            for _, t in batch:
                out["shared"][f"{t['user_id']}\n{t['device_id']}"] = t["curve25519"]
            self.st.save()

    def send(self, room: str, text: str, file: str | None = None) -> dict:
        members = [m["user_id"] for m in self.s.call("GET", f"/api/v1/rooms/{urllib.parse.quote(room)}").get("members", [])]
        targets = self.trusted_devices(sorted(set(members) | {self.user_id}))
        g = self.outbound(room, members, targets)
        self.share(room, g, targets)
        ref = "ref_" + uuid.uuid4().hex
        files, att_ids = [], []
        if file:
            with open(file, "rb") as f:
                data = f.read()
            ct, desc = encrypt_blob(data)
            att = self.upload_ciphertext(room, ct)
            desc.update(attachment_id=att, name=os.path.basename(file), mime_type="application/octet-stream")
            files.append(desc)
            att_ids.append(att)
        inner = {"room_id": room, "type": "attachment" if files else "text", "body": text, "files": files, "ref": ref}
        ciphertext = g.encrypt(json.dumps(inner).encode()).to_base64()
        self.st["outbound"][room]["pickle"] = g.pickle(self.st.key)
        self.st.save()
        env = {"alg": "megolm.v1", "sender_key": self.account().curve25519_key.to_base64(), "device_id": self.device_id, "session_id": g.session_id, "ciphertext": ciphertext}
        return self.s.call("POST", f"/api/v1/rooms/{urllib.parse.quote(room)}/messages",
                           {"body": json.dumps(env), "encoding": "e2ee_room_v1", "idempotency_key": ref, "attachment_ids": att_ids})["message"]

    def upload_ciphertext(self, room: str, ct: bytes) -> str:
        boundary = "kybot" + secrets.token_hex(12)
        body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"encrypted.bin\"\r\n"
                f"Content-Type: application/octet-stream\r\n\r\n").encode() + ct + f"\r\n--{boundary}--\r\n".encode()
        r = self.s.call("POST", f"/api/v1/rooms/{urllib.parse.quote(room)}/attachments?encrypted=1", raw=body, ctype=f"multipart/form-data; boundary={boundary}")
        return r["attachment"]["id"]

    def download(self, room: str, message_id: str, att: str) -> bytes:
        m = self.s.call("GET", f"/api/v1/rooms/{urllib.parse.quote(room)}/messages/{urllib.parse.quote(message_id)}")["message"]
        opened = self.open(m)
        if "error" in opened:
            raise SystemExit(opened["error"])
        env = json.loads(m["body"])
        rec = self.st["inbound"][f"{env['sender_key']}\n{env['session_id']}"]
        inner = json.loads(vz.InboundGroupSession.from_pickle(rec["pickle"], self.st.key).decrypt(vz.MegolmMessage.from_base64(env["ciphertext"])).plaintext)
        d = next((f for f in inner.get("files") or [] if isinstance(f, dict) and f.get("attachment_id") == att), None)
        if not d or att not in {a.get("id") for a in m.get("attachments") or []} or d.get("ciphertext_size", 0) > MAX_CIPHERTEXT:
            raise SystemExit("this message names no such file")
        return decrypt_blob(self.s.get_bytes(f"/api/v1/attachments/{urllib.parse.quote(att)}", d["ciphertext_size"]), d)

    def accept(self, user: str) -> None:
        """Accept a member's changed identity (after checking it with them out of band)."""
        for k in [k for k in self.st["changed"] if k.endswith(":" + user)]:
            self.st["pins"][k] = self.st["changed"].pop(k)
        self.st.save()


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--state", default=os.environ.get("KYBOT_STATE", os.path.expanduser("~/.kymessages-bot.json")))
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init")
    sub.add_parser("sync")
    r = sub.add_parser("read")
    r.add_argument("room")
    r.add_argument("--limit", type=int, default=50)
    s = sub.add_parser("send")
    s.add_argument("room")
    s.add_argument("text")
    s.add_argument("--file")
    d = sub.add_parser("download")
    for a in ("room", "message", "attachment", "out"):
        d.add_argument(a)
    sub.add_parser("decrypt")
    a = sub.add_parser("accept")
    a.add_argument("user")
    args = ap.parse_args(argv)
    url, token = os.environ.get("KYMESSAGES_SERVER_URL"), os.environ.get("KYMESSAGES_ACCESS_TOKEN")
    if not url or not token:
        raise SystemExit("set KYMESSAGES_SERVER_URL and KYMESSAGES_ACCESS_TOKEN (a kybot_ token)")
    bot = Bot(Server(url, token), State(args.state))
    if args.cmd != "init" and "account" not in bot.st.d:
        raise SystemExit("run `kybot.py init` first")
    if args.cmd == "init":
        out = bot.init()
        print(json.dumps(out))
        print(f"Ask your owner to vouch for device {out['device_id']} in KyMessages (Your bots) and check that it shows the code {out['code']}.", file=sys.stderr)
    elif args.cmd == "sync":
        print(json.dumps({"sessions": bot.sync()}))
    elif args.cmd == "read":
        bot.sync()
        for m in bot.read(args.room, args.limit):
            print(json.dumps(m))
    elif args.cmd == "send":
        print(json.dumps(bot.send(args.room, args.text, args.file)))
    elif args.cmd == "download":
        bot.sync()
        data = bot.download(args.room, args.message, args.attachment)
        fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
    elif args.cmd == "decrypt":
        bot.sync()
        print(json.dumps(bot.open(json.load(sys.stdin))))
        bot.st.save()
    elif args.cmd == "accept":
        bot.accept(args.user)


if __name__ == "__main__":
    main()
