"""Tests for the bot device bundle (agent-skill/kymessages/scripts/kybot.py), E4.

Run: python3 -B -m unittest discover -s agent-skill/tests (with requirements.txt installed).
The shared vectors are the Go identity layer's (internal/e2eeid/testdata/vectors.json) and the
attachment format's (web/src/crypto/attachments.test.ts). FakeServer plays the key server,
honest or hostile; people are modelled with the same trust code as the browser's, plus a master
key that signs their devices.
"""
import hashlib
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "agent-skill" / "kymessages" / "scripts"))
import kybot  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa  # noqa: E402


class Master:
    """A person's hybrid master key (ky-primitives hybridsig), for tests only: bots never hold one."""

    def __init__(self):
        self.m = mldsa.MLDSA65PrivateKey.generate()
        self.e = ed25519.Ed25519PrivateKey.generate()
        raw = lambda k: k.public_bytes_raw()
        self.public = kybot.b64(kybot.TAG + raw(self.m.public_key()) + raw(self.e.public_key()))

    def sign(self, label: str, msg: bytes) -> str:
        d = hashlib.sha256(label.encode() + b"\0" + msg).digest()
        return kybot.b64(kybot.TAG + self.m.sign(d) + self.e.sign(d))


TENANT = "00000000-0000-4000-8000-00000000000a"


class FakeServer:
    """The key server, room membership and messages, as internal/api serves them."""

    def __init__(self):
        self.devices, self.otks, self.mail, self.masters, self.bot_lists = {}, {}, {}, {}, {}
        self.rooms, self.messages, self.blobs, self.next = {}, {}, {}, 1

    def as_(self, user):
        srv = self

        class S:
            def call(self, method, path, body=None, raw=None, ctype=None):
                return srv.handle(user, method, path, body, raw)

            def get_bytes(self, path, limit):
                data = srv.blobs[path.rsplit("/", 1)[1]]
                if len(data) > limit:
                    raise ValueError("too large")
                return data
        return S()

    def handle(self, user, method, path, body, raw):
        p, _, q = path.partition("?")
        if p == "/api/auth/me":
            return {"user": {"id": user}}
        if p == "/api/v1/keys/upload":
            dev = self.devices.setdefault(user, {}).get(body["device_id"])
            if body.get("device_keys"):
                k = body["device_keys"]
                assert kybot.ed_verify(k["ed25519"], kybot.device_signed(user, body["device_id"], k["curve25519"], k["ed25519"]), k["signature"])
                dev = self.devices[user][body["device_id"]] = {"device_id": body["device_id"], **k}
            box = self.otks.setdefault((user, dev["device_id"]), [])
            for k in body["one_time_keys"]:
                assert kybot.ed_verify(dev["ed25519"], kybot.otk_signed(user, dev["device_id"], k["key_id"], k["key"]), k["signature"])
                box.append(k)
            return {"one_time_key_count": len(box)}
        if p == "/api/v1/keys/query":
            out = {"tenant_id": TENANT, "devices": {}, "master_keys": {}, "bot_devices": {}}
            for u in body["user_ids"]:
                out["devices"][u] = [dict(d) for d in self.devices.get(u, {}).values()]
                if u in self.masters:
                    out["master_keys"][u] = json.loads(json.dumps(self.masters[u]))
                if u in self.bot_lists:
                    lst = self.bot_lists[u]
                    out["bot_devices"][u] = json.loads(json.dumps(lst))
                    out["master_keys"][lst["owner_id"]] = json.loads(json.dumps(self.masters[lst["owner_id"]]))
            return out
        if p == "/api/v1/keys/claim":
            keys = []
            for d in body["devices"]:
                box = self.otks.get((d["user_id"], d["device_id"]), [])
                if box:
                    keys.append({**d, **box.pop(0), "fallback": False})
            return {"keys": keys}
        if p == "/api/v1/to-device" and method == "PUT":
            sender = self.devices[user][body["device_id"]]
            for m in body["messages"]:
                box = self.mail.setdefault((m["user_id"], m["device_id"]), [])
                box.append({"id": self.next, "sender_user_id": user, "sender_device_id": body["device_id"], "sender_keys": dict(sender), "type": m["type"], "content": m["content"]})
                self.next += 1
            return {}
        if p == "/api/v1/to-device":
            dev = q.split("=", 1)[1]
            return {"messages": list(self.mail.get((user, dev), []))[:100]}
        if p == "/api/v1/to-device/ack":
            k = (user, body["device_id"])
            self.mail[k] = [m for m in self.mail.get(k, []) if m["id"] not in body["ids"]]
            return {}
        parts = p.split("/")
        if p.startswith("/api/v1/rooms/") and len(parts) == 5 and method == "GET":
            return {"members": [{"user_id": u} for u in self.rooms[parts[4]]]}
        if p.endswith("/attachments") and method == "POST":
            assert q == "encrypted=1"
            att = f"att_{self.next}"
            self.next += 1
            data = raw.split(b"\r\n\r\n", 1)[1].rsplit(b"\r\n--", 1)[0]
            self.blobs[att] = data
            return {"attachment": {"id": att}}
        if p.endswith("/messages") and method == "POST":
            assert body["encoding"] == "e2ee_room_v1"
            m = {"id": f"msg_{self.next}", "room_id": parts[4], "sender_id": user, "encoding": "e2ee_room_v1", "body": body["body"],
                 "attachments": [{"id": a} for a in body.get("attachment_ids", [])]}
            self.next += 1
            self.messages.setdefault(parts[4], []).append(m)
            return {"message": m}
        if p.endswith("/messages"):
            return {"messages": list(self.messages.get(parts[4], []))}
        if "/messages/" in p:
            return {"message": next(m for m in self.messages[parts[4]] if m["id"] == parts[6])}
        raise AssertionError(f"unexpected {method} {path}")


class Env:
    def __init__(self):
        self.dir = tempfile.mkdtemp()
        self.server = FakeServer()
        self.identities = {}

    def device(self, user):
        b = kybot.Bot(self.server.as_(user), kybot.State(os.path.join(self.dir, f"{user}-{secrets.token_hex(3)}.json")))
        b.init()
        return b

    def person(self, user):
        """A person's verified device: their master key signs and lists it."""
        d = self.device(user)
        m = self.identities.get(user) or Master()
        self.identities[user] = m
        dev = self.server.devices[user][d.device_id]
        dev["master_signature"] = m.sign(kybot.DOMAIN_DEVICE, kybot.device_msg(TENANT, user, d.device_id, dev["curve25519"], dev["ed25519"]))
        ids = sorted(self.server.devices[user])
        rec = self.server.masters.get(user, {"version": 1, "master_key": m.public, "self_signature": m.sign(kybot.DOMAIN_MASTER, kybot.master_self_msg(TENANT, user, m.public))})
        epoch = rec.get("device_list", {}).get("epoch", 0) + 1
        rec["device_list"] = {"epoch": epoch, "device_ids": ids, "signature": m.sign(kybot.DOMAIN_DEVICE_LIST, kybot.device_list_msg(TENANT, user, 1, epoch, ids))}
        self.server.masters[user] = rec
        return d

    def vouch(self, owner, bot, *devices, epoch=None):
        """What the owner's browser signs (engine.vouchForBot)."""
        devs = sorted(({k: self.server.devices[bot][d.device_id][k] for k in ("device_id", "curve25519", "ed25519")} for d in devices), key=lambda d: d["device_id"])
        epoch = epoch or self.server.bot_lists.get(bot, {}).get("epoch", 0) + 1
        sig = self.identities[owner].sign(kybot.DOMAIN_BOT_DEVICES, kybot.bot_devices_msg(TENANT, owner, 1, bot, epoch, devs))
        self.server.bot_lists[bot] = {"owner_id": owner, "version": 1, "epoch": epoch, "devices": devs, "signature": sig}

    def mail_to(self, d):
        return len(self.server.mail.get((d.user_id, d.device_id), []))

    def close(self):
        shutil.rmtree(self.dir)


class Vectors(unittest.TestCase):
    def test_shared_identity_vectors(self):
        vs = json.loads((ROOT / "internal/e2eeid/testdata/vectors.json").read_text())
        checked = 0
        for v in vs:
            a = v["args"]
            if v["call"] == "verifyMaster":
                got = kybot.hybrid_verify(a[0], kybot.DOMAIN_MASTER, kybot.master_self_msg(a[1], a[2], a[0]), a[3])
            elif v["call"] == "verifyDevice":
                got = kybot.hybrid_verify(a[0], kybot.DOMAIN_DEVICE, kybot.device_msg(*a[1:6]), a[6])
            elif v["call"] == "verifyDeviceList":
                got = kybot.hybrid_verify(a[0], kybot.DOMAIN_DEVICE_LIST, kybot.device_list_msg(a[1], a[2], int(a[3]), int(a[4]), json.loads(a[5])), a[6])
            elif v["call"] == "verifyBotDevices":
                try:
                    msg = kybot.bot_devices_msg(a[1], a[2], int(a[3]), a[4], int(a[5]), json.loads(a[6]))
                except ValueError:
                    msg = b""
                got = kybot.hybrid_verify(a[0], kybot.DOMAIN_BOT_DEVICES, msg, a[7])
            elif v["call"] == "fingerprint":
                got = kybot.fingerprint(a[0])
            elif v["call"] == "hash":
                got = kybot.phash(*a)
            else:
                continue
            self.assertEqual(got, v["want"], v["name"])
            checked += 1
        self.assertGreaterEqual(checked, 20)

    def test_attachment_vectors(self):
        key, prefix = bytes(range(32)), bytes(range(0xA0, 0xA7))
        for plain, kind, want in [(b"kymessages E5\n", "file", "1c18247bcb7581a76616f86afa84b6456f84e4858733d855d93953ef10cf"),
                                  (b"kymessages E5\n", "thumb", "1c18247bcb7581a76616f86afa84566008d177da68c400447c958cdd589e"),
                                  (b"", "file", "fe8f4d8f2a70be445ccf44c61529c1a7")]:
            ct, d = kybot.encrypt_blob(plain, kind, 4096, key, prefix)
            self.assertEqual(ct.hex(), want)
            self.assertEqual(kybot.decrypt_blob(ct, d, kind), plain)
        ct, d = kybot.encrypt_blob(b"a" * 4097, "file", 4096, key, prefix)
        self.assertEqual(d["sha256"], "222d3b03c6732738bb7e1389041ff20fa82dbb3e3fa702c9d5cf801c0b6ead52")
        self.assertEqual(ct[-17:].hex(), "88e30951e758972e0158b775caafcf1920")
        with self.assertRaises(Exception):
            kybot.decrypt_blob(ct, d, "thumb")  # a file never opens as a thumbnail

    def test_device_code_matches_the_browser(self):
        # The same inputs as web/src/crypto/bots.test.ts.
        self.assertEqual(kybot.device_code("bot_helper", "BOTDEVICE1", "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU", "MDEyMzQ1Njc4OWFiY2RlZmdoaWprbG1ub3BxcnN0dXY"),
                         BOT_CODE_VECTOR)


# web/src/crypto/bots.test.ts pins the same value.
BOT_CODE_VECTOR = "a375-b438-12e4-6bba-55a7"


class Trust(unittest.TestCase):
    def setUp(self):
        self.env = Env()
        self.alice = self.env.person("u_alice")
        self.bot = self.env.device("bot_helper")
        self.env.server.rooms["r1"] = ["u_alice", "bot_helper"]

    def tearDown(self):
        self.env.close()

    def test_a_vouched_bot_and_its_owner_read_each_other(self):
        self.env.vouch("u_alice", "bot_helper", self.bot)
        sent = self.bot.send("r1", "build passed")
        self.alice.sync()
        self.assertEqual(self.alice.open(sent)["body"], "build passed")
        reply = self.alice.send("r1", "thanks")
        self.bot.sync()
        self.assertEqual(self.bot.open(reply)["body"], "thanks")

    def test_an_unvouched_bot_gets_no_keys_and_its_keys_are_refused(self):
        self.alice.send("r1", "secret")
        self.assertEqual(self.env.mail_to(self.bot), 0)
        # The bot still shares with Alice (it trusts her), but her device trusts no unvouched bot.
        sent = self.bot.send("r1", "hello")
        self.assertEqual(self.alice.sync(), [])
        self.assertIn("error", self.alice.open(sent))

    def test_a_list_not_signed_by_the_owner_vouches_for_nothing(self):
        self.env.vouch("u_alice", "bot_helper", self.bot)
        self.env.server.bot_lists["bot_helper"]["signature"] = Master().sign(kybot.DOMAIN_BOT_DEVICES, b"x")
        self.alice.send("r1", "secret")
        self.assertEqual(self.env.mail_to(self.bot), 0)

    def test_a_revoked_bot_gets_no_new_keys_even_after_a_rollback(self):
        self.env.vouch("u_alice", "bot_helper", self.bot)
        self.alice.send("r1", "while trusted")
        self.assertEqual(self.env.mail_to(self.bot), 1)
        old = json.loads(json.dumps(self.env.server.bot_lists["bot_helper"]))
        self.env.vouch("u_alice", "bot_helper")  # revoked: an empty list at the next epoch
        self.alice.send("r1", "after revocation")
        self.assertEqual(self.env.mail_to(self.bot), 1)
        self.env.server.bot_lists["bot_helper"] = old
        self.alice.send("r1", "after rollback")
        self.assertEqual(self.env.mail_to(self.bot), 1)

    def test_the_server_cannot_add_a_device_or_swap_keys(self):
        self.env.vouch("u_alice", "bot_helper", self.bot)
        # A device the server made for Alice, self-signed but neither cross-signed nor listed.
        evil = self.env.device("u_alice")
        self.bot.send("r1", "hello")
        self.assertEqual(self.env.mail_to(evil), 0)
        # A device spliced into the owner's list, or the bot's keys swapped.
        rogue = self.env.device("bot_helper")
        lst = self.env.server.bot_lists["bot_helper"]
        lst["devices"] = sorted(lst["devices"] + [{k: self.env.server.devices["bot_helper"][rogue.device_id][k] for k in ("device_id", "curve25519", "ed25519")}], key=lambda d: d["device_id"])
        self.alice.send("r1", "spliced")
        self.assertEqual(self.env.mail_to(rogue), 0)

    def test_a_device_off_the_list_gets_nothing_though_still_cross_signed(self):
        second = self.env.person("u_alice")
        self.bot.send("r1", "both listed")
        self.assertEqual(self.env.mail_to(second), 1)
        # Alice removes it; its row and old cross-signature stay on the server.
        m, rec = self.env.identities["u_alice"], self.env.server.masters["u_alice"]
        ids, epoch = [self.alice.device_id], rec["device_list"]["epoch"] + 1
        rec["device_list"] = {"epoch": epoch, "device_ids": ids, "signature": m.sign(kybot.DOMAIN_DEVICE_LIST, kybot.device_list_msg(TENANT, "u_alice", 1, epoch, ids))}
        del self.bot.st["outbound"]["r1"]  # a new session, as after any rotation
        self.bot.send("r1", "after removal")
        self.assertEqual(self.env.mail_to(second), 1)

    def test_a_bot_device_with_swapped_keys_gets_nothing(self):
        import vodozemac as vz
        self.env.vouch("u_alice", "bot_helper", self.bot)
        # The server keeps the vouched device ID but serves keys of its own, self-signed.
        acct = vz.Account()
        curve, ed = acct.curve25519_key.to_base64(), acct.ed25519_key.to_base64()
        self.env.server.devices["bot_helper"][self.bot.device_id] = {"device_id": self.bot.device_id, "curve25519": curve, "ed25519": ed,
                                                                      "signature": acct.sign(kybot.device_signed("bot_helper", self.bot.device_id, curve, ed)).to_base64()}
        # With one-time keys of its own, signed by its key, so an Olm session would open.
        acct.generate_one_time_keys(1)
        self.env.server.otks[("bot_helper", self.bot.device_id)] = [
            {"key_id": k, "key": v.to_base64(), "signature": acct.sign(kybot.otk_signed("bot_helper", self.bot.device_id, k, v.to_base64())).to_base64()}
            for k, v in acct.one_time_keys.items()]
        fresh = self.env.person("u_alice")  # has never seen the bot's real keys
        fresh.send("r1", "to the bot?")
        self.assertEqual(self.env.mail_to(self.bot), 0)

    def test_room_keys_from_devices_nobody_vouches_for_are_refused(self):
        mallory = self.env.device("u_mallory")  # no master key
        self.env.server.rooms["r1"].append("u_mallory")
        # Mallory's device shares with the bot regardless (her client trusts the bot's devices
        # as the server lists them), then posts: the bot refuses the key and cannot read it.
        q = mallory.s.call("POST", "/api/v1/keys/query", {"user_ids": ["bot_helper"]})
        targets = [mallory.check_device("bot_helper", d) for d in q["devices"]["bot_helper"]]
        g = mallory.outbound("r1", ["bot_helper"], targets)
        mallory.share("r1", g, targets)
        self.assertEqual(self.bot.sync(), [])

    def test_a_changed_identity_stops_sharing_until_accepted(self):
        self.bot.send("r1", "first")  # pins Alice
        self.env.identities["u_alice"] = Master()
        del self.env.server.masters["u_alice"]
        newer = self.env.person("u_alice")
        self.bot.send("r1", "after the change")
        self.assertEqual(self.env.mail_to(newer), 0)
        self.bot.accept("u_alice")
        self.bot.send("r1", "accepted")
        self.assertEqual(self.env.mail_to(newer), 1)

    def test_files_are_encrypted_both_ways(self):
        self.env.vouch("u_alice", "bot_helper", self.bot)
        path = os.path.join(self.env.dir, "report.txt")
        Path(path).write_bytes(b"quarterly numbers\n" * 5000)
        sent = self.bot.send("r1", "the report", file=path)
        att = sent["attachments"][0]["id"]
        self.assertNotIn(b"quarterly", self.env.server.blobs[att])
        self.alice.sync()
        self.assertEqual(self.alice.download("r1", sent["id"], att), Path(path).read_bytes())


HAVE_CORE = bool(shutil.which("node")) and (ROOT / "web/src/crypto/pkg/kycrypto_bg.wasm").exists()
if os.environ.get("KYBOT_REQUIRE_INTEROP") and not HAVE_CORE:
    raise SystemExit("KYBOT_REQUIRE_INTEROP: node and web/src/crypto/pkg (npm run build:crypto) are required")


@unittest.skipUnless(HAVE_CORE, "needs node and the built web crypto core")
class BrowserCore(unittest.TestCase):
    """Olm and Megolm between this bundle and the browser's own crypto core (web/crypto)."""

    def test_olm_and_megolm_interoperate(self):
        import vodozemac as vz
        script = ROOT / "agent-skill/tests/interop.mjs"
        browser = json.loads(subprocess.run(["node", str(script), "keys"], check=True, capture_output=True, text=True, cwd=ROOT / "web").stdout)
        acct = vz.Account()
        s = acct.create_outbound_session(vz.Curve25519PublicKey.from_base64(browser["curve25519"]), vz.Curve25519PublicKey.from_base64(browser["otk"]))
        g = vz.GroupSession()
        typ, ct = s.encrypt(json.dumps({"session_key": g.session_key.to_base64()}).encode()).to_parts()
        msg = g.encrypt(b"hello from a bot").to_base64()
        args = ["node", str(script), "open", browser["pickle"], acct.curve25519_key.to_base64(), str(typ), kybot.b64(ct), msg]
        back = json.loads(subprocess.run(args, check=True, capture_output=True, text=True, cwd=ROOT / "web").stdout)
        self.assertEqual(back["megolm"], "hello from a bot")
        # And the browser's Megolm session opens here.
        ig = vz.InboundGroupSession(vz.SessionKey(back["session_key"]))
        self.assertEqual(ig.decrypt(vz.MegolmMessage.from_base64(back["reply"])).plaintext, b"hello from a browser")


if __name__ == "__main__":
    unittest.main()
