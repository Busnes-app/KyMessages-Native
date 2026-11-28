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
        self.tenant, self.fail_to_device, self.reads, self.ignore_after = TENANT, 0, 0, False
        self.lose_upload, self.claims = 0, []
        self.devices, self.otks, self.mail, self.masters, self.bot_lists = {}, {}, {}, {}, {}
        self.fallbacks, self.spent = {}, set()
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
            d = (user, dev["device_id"])
            box = self.otks.setdefault(d, [])
            for k in body["one_time_keys"] + ([body["fallback_key"]] if "fallback_key" in body else []):
                assert kybot.ed_verify(dev["ed25519"], kybot.otk_signed(user, dev["device_id"], k["key_id"], k["key"]), k["signature"])
            for k in body["one_time_keys"]:
                # As the store: a key ID keeps its first value, and a spent one never returns.
                if (d, k["key_id"]) not in self.spent and all(x["key_id"] != k["key_id"] for x in box):
                    box.append(k)
            assert len(box) <= 100, "Too many one-time keys stored for this device"
            if "fallback_key" in body:
                self.fallbacks[d] = body["fallback_key"]
            if self.lose_upload and body["one_time_keys"]:  # stored, but the response never arrives
                self.lose_upload -= 1
                raise SystemExit("POST /api/v1/keys/upload: connection reset")
            return {"one_time_key_count": len(box), "has_fallback_key": d in self.fallbacks}
        if p == "/api/v1/keys/query":
            out = {"tenant_id": self.tenant, "devices": {}, "master_keys": {}, "bot_devices": {}}
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
            if not 1 <= len(body["devices"]) <= 100:
                raise SystemExit("POST /api/v1/keys/claim: HTTP 400 Name 1 to 100 devices")
            self.claims.append(len(body["devices"]))
            keys = []
            for d in body["devices"]:
                k = (d["user_id"], d["device_id"])
                box = self.otks.get(k, [])
                if box:
                    self.spent.add((k, box[0]["key_id"]))
                    keys.append({**d, **box.pop(0), "fallback": False})
                elif k in self.fallbacks:
                    keys.append({**d, **self.fallbacks[k], "fallback": True})
            return {"keys": keys}
        if p == "/api/v1/to-device" and method == "PUT":
            if self.fail_to_device:
                self.fail_to_device -= 1
                raise SystemExit("PUT /api/v1/to-device: HTTP 429")
            sender = self.devices[user][body["device_id"]]
            for m in body["messages"]:
                box = self.mail.setdefault((m["user_id"], m["device_id"]), [])
                box.append({"id": self.next, "sender_user_id": user, "sender_device_id": body["device_id"], "sender_keys": dict(sender), "type": m["type"], "content": m["content"]})
                self.next += 1
            return {}
        if p == "/api/v1/to-device":
            self.reads += 1
            args = dict(a.split("=", 1) for a in q.split("&"))
            after = 0 if self.ignore_after else int(args.get("after", 0))
            return {"messages": [m for m in self.mail.get((user, args["device_id"]), []) if m["id"] > after][:100]}
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
        if "/messages/" in p and method == "PATCH":
            m = next(m for m in self.messages[parts[4]] if m["id"] == parts[6])
            # As the store: the first envelope of an e2ee message with files is kept once edited.
            if m["attachments"] and not m.get("edited"):
                m["original_body"] = m["body"]
            m["body"], m["edited"] = body["body"], True
            return {"message": m}
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


def vz_group(bot, room):
    import vodozemac as vz
    return vz.GroupSession.from_pickle(bot.st["outbound"][room]["pickle"], bot.st.key)


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
        self.env.server.mail.clear()
        self.old_master = json.loads(json.dumps(self.env.server.masters["u_alice"]))
        self.env.identities["u_alice"] = Master()
        del self.env.server.masters["u_alice"]
        newer = self.env.person("u_alice")
        self.bot.send("r1", "after the change")
        self.assertEqual(self.env.mail_to(newer), 0)
        # The server going back to the old identity does not lift the block.
        changed = self.env.server.masters["u_alice"]
        self.env.server.masters["u_alice"] = self.old_master
        self.bot.send("r1", "old identity restored")
        self.env.server.masters["u_alice"] = changed
        self.assertEqual(self.env.mail_to(self.alice), 0)
        self.bot.accept("u_alice")
        self.bot.send("r1", "accepted")
        self.assertEqual(self.env.mail_to(newer), 1)

    def change_identity(self):
        """Alice resets her identity on a new device and vouches for the bot again."""
        self.bot.send("r1", "pins Alice")
        self.env.server.mail.clear()
        self.env.identities["u_alice"] = Master()
        del self.env.server.masters["u_alice"]
        newer = self.env.person("u_alice")
        self.env.vouch("u_alice", "bot_helper", self.bot)
        return newer

    def test_room_keys_awaiting_accept_are_kept_and_read_after_it(self):
        newer = self.change_identity()
        sent = newer.send("r1", "after my reset")
        self.assertEqual(self.bot.sync(), [])
        self.assertEqual(self.env.mail_to(self.bot), 1)  # kept, not acknowledged
        self.assertIn("error", self.bot.open(sent))
        self.bot.accept("u_alice")
        self.assertEqual(len(self.bot.sync()), 1)
        self.assertEqual(self.env.mail_to(self.bot), 0)
        self.assertEqual(self.bot.open(sent)["body"], "after my reset")

    def test_a_page_of_kept_mail_neither_loops_nor_blocks_later_mail(self):
        newer = self.change_identity()
        newer.send("r1", "kept")
        box = self.env.server.mail[(self.bot.user_id, self.bot.device_id)]
        for _ in range(150):  # more than a page of mail awaiting accept
            box.append({**box[0], "id": self.env.server.next})
            self.env.server.next += 1
        carol = self.env.person("u_carol")
        self.env.server.rooms["r1"].append("u_carol")
        sent = carol.send("r1", "behind the kept mail")
        self.bot.sync()
        self.assertEqual(self.bot.open(sent)["body"], "behind the kept mail")
        self.assertEqual(self.env.mail_to(self.bot), 151)
        self.assertLessEqual(self.env.server.reads, 3)
        # A server that ignores `after` gets one read of the kept page, not a loop.
        self.env.server.ignore_after, self.env.server.reads = True, 0
        self.bot.sync()
        self.assertEqual(self.env.server.reads, 2)

    def test_another_org_is_refused_before_any_trust_changes(self):
        self.bot.send("r1", "pins Alice and the org")
        pins = dict(self.bot.st["pins"])
        self.env.server.mail.clear()
        self.env.server.tenant = "00000000-0000-4000-8000-00000000000b"
        with self.assertRaises(SystemExit):
            self.bot.send("r1", "elsewhere")
        self.assertEqual(self.bot.st["pins"], pins)
        self.assertEqual(self.env.mail_to(self.alice), 0)

    def test_a_bots_owner_is_pinned(self):
        carol = self.env.person("u_carol")
        self.env.server.rooms["r1"].append("u_carol")
        self.env.vouch("u_alice", "bot_helper", self.bot)
        carol.send("r1", "pins Alice as the bot's owner")
        self.assertEqual(self.env.mail_to(self.bot), 1)
        # The server names Mallory, a real colleague, who signs a list with her own device.
        self.env.person("u_mallory")
        rogue = self.env.device("bot_helper")
        del self.env.server.bot_lists["bot_helper"]
        self.env.vouch("u_mallory", "bot_helper", rogue, epoch=1)
        del carol.st["outbound"]["r1"]
        carol.send("r1", "after the owner swap")
        self.assertEqual(self.env.mail_to(rogue), 0)

    def test_a_malformed_message_fails_alone(self):
        self.env.vouch("u_alice", "bot_helper", self.bot)
        first = self.alice.send("r1", "one")
        g = vz_group(self.alice, "r1")
        bad = self.env.server.handle("u_alice", "POST", "/api/v1/rooms/r1/messages", {"encoding": "e2ee_room_v1", "body": json.dumps({
            "alg": "megolm.v1", "sender_key": self.alice.account().curve25519_key.to_base64(), "device_id": self.alice.device_id,
            "session_id": g.session_id, "ciphertext": g.encrypt(b"not json").to_base64()})}, None)["message"]
        self.alice.st["outbound"]["r1"]["pickle"] = g.pickle(self.alice.st.key)
        last = self.alice.send("r1", "three")
        self.bot.sync()
        got = {m["id"]: m for m in self.bot.read("r1", 50)}
        self.assertEqual(got[first["id"]]["body"], "one")
        self.assertEqual(got[last["id"]]["body"], "three")
        self.assertEqual(got[bad["id"]]["error"], "damaged")

    def test_a_recursion_bomb_fails_alone(self):
        self.env.vouch("u_alice", "bot_helper", self.bot)
        first = self.alice.send("r1", "one")
        g = vz_group(self.alice, "r1")
        bomb = b"[" * 100000 + b"]" * 100000  # json.loads raises RecursionError
        bad = self.env.server.handle("u_alice", "POST", "/api/v1/rooms/r1/messages", {"encoding": "e2ee_room_v1", "body": json.dumps({
            "alg": "megolm.v1", "sender_key": self.alice.account().curve25519_key.to_base64(), "device_id": self.alice.device_id,
            "session_id": g.session_id, "ciphertext": g.encrypt(bomb).to_base64()})}, None)["message"]
        self.alice.st["outbound"]["r1"]["pickle"] = g.pickle(self.alice.st.key)
        last = self.alice.send("r1", "three")
        self.bot.sync()
        got = {m["id"]: m for m in self.bot.read("r1", 50)}
        self.assertEqual(got[first["id"]]["body"], "one")
        self.assertEqual(got[last["id"]]["body"], "three")
        self.assertEqual(got[bad["id"]]["error"], "damaged")
        self.assertEqual([m["id"] for m in got.values() if "error" in m], [bad["id"]])

    def sign_out(self, d):
        """d signs out, as the browser does: off Alice's signed list, then its row deleted."""
        m, rec = self.env.identities["u_alice"], self.env.server.masters["u_alice"]
        del self.env.server.devices["u_alice"][d.device_id]
        ids, epoch = sorted(self.env.server.devices["u_alice"]), rec["device_list"]["epoch"] + 1
        rec["device_list"] = {"epoch": epoch, "device_ids": ids, "signature": m.sign(kybot.DOMAIN_DEVICE_LIST, kybot.device_list_msg(TENANT, "u_alice", 1, epoch, ids))}

    def test_room_keys_from_a_device_signed_out_since_are_read(self):
        self.env.vouch("u_alice", "bot_helper", self.bot)
        phone = self.env.person("u_alice")
        sent = phone.send("r1", "sent before sign-out")
        self.sign_out(phone)
        self.bot.sync()
        self.assertEqual(self.bot.open(sent)["body"], "sent before sign-out")

    def test_a_signed_out_device_the_master_never_signed_is_refused(self):
        self.env.vouch("u_alice", "bot_helper", self.bot)
        for forged in (False, True):
            d = self.env.device("u_alice")  # never cross-signed or listed
            if forged:  # a cross-signature by some other key
                dev = self.env.server.devices["u_alice"][d.device_id]
                dev["master_signature"] = Master().sign(kybot.DOMAIN_DEVICE, kybot.device_msg(TENANT, "u_alice", d.device_id, dev["curve25519"], dev["ed25519"]))
            sent = d.send("r1", "from an unsigned device")
            self.assertEqual(self.env.mail_to(self.bot), 1)
            self.sign_out(d)
            self.assertEqual(self.bot.sync(), [])
            self.assertEqual(self.env.mail_to(self.bot), 0)
            self.assertIn("error", self.bot.open(sent))

    def post_inner(self, sender, inner, method="POST", mid=None):
        """A message sender's device sealed with its room session, whatever inner says."""
        g = vz_group(sender, "r1")
        env = json.dumps({"alg": "megolm.v1", "sender_key": sender.account().curve25519_key.to_base64(), "device_id": sender.device_id,
                          "session_id": g.session_id, "ciphertext": g.encrypt(json.dumps(inner).encode()).to_base64()})
        sender.st["outbound"]["r1"]["pickle"] = g.pickle(sender.st.key)
        path = "/api/v1/rooms/r1/messages" + (f"/{mid}" if mid else "")
        return self.env.server.handle(sender.user_id, method, path, {"encoding": "e2ee_room_v1", "body": env}, None)["message"]

    def test_malformed_file_metadata_fails_alone(self):
        self.env.vouch("u_alice", "bot_helper", self.bot)
        first = self.alice.send("r1", "one")
        bad = [self.post_inner(self.alice, {"room_id": "r1", "type": "attachment", "body": "x", "files": f, "ref": "r"}) for f in ("nope", [{"attachment_id": 5}], [7])]
        last = self.alice.send("r1", "three")
        self.bot.sync()
        got = {m["id"]: m for m in self.bot.read("r1", 50)}
        self.assertEqual((got[first["id"]]["body"], got[last["id"]]["body"]), ("one", "three"))
        self.assertEqual(got[bad[0]["id"]]["error"], "damaged")
        self.assertNotIn("files", got[bad[1]["id"]])

    def test_an_edited_messages_file_comes_from_its_first_envelope(self):
        self.env.vouch("u_alice", "bot_helper", self.bot)
        path = os.path.join(self.env.dir, "f.bin")
        Path(path).write_bytes(b"first envelope file")
        sent = self.bot.send("r1", "caption", file=path)
        own = self.bot.opened(sent)
        inner_ref = self.bot._inner(sent, sent["body"])[0]["ref"]
        self.post_inner(self.bot, {"room_id": "r1", "type": "edit", "message_id": sent["id"], "body": "new caption",
                                   "original": {"kind": "e5", "ref": inner_ref, "files": 1}}, method="PATCH", mid=sent["id"])
        self.alice.sync()
        att = sent["attachments"][0]["id"]
        self.assertEqual(self.alice.download("r1", sent["id"], att), b"first envelope file")
        # An edit naming another message's ref gets no files.
        self.post_inner(self.bot, {"room_id": "r1", "type": "edit", "message_id": sent["id"], "body": "moved",
                                   "original": {"kind": "e5", "ref": "ref_other", "files": 1}}, method="PATCH", mid=sent["id"])
        with self.assertRaises(SystemExit):
            self.alice.download("r1", sent["id"], att)
        self.assertTrue(own[1])

    def test_a_failed_delivery_is_sent_again(self):
        self.env.vouch("u_alice", "bot_helper", self.bot)
        self.env.server.fail_to_device = 1
        with self.assertRaises(SystemExit):
            self.alice.send("r1", "lost")
        self.assertEqual(self.env.mail_to(self.bot), 0)
        sent = self.alice.send("r1", "retried")
        self.bot.sync()
        self.assertEqual(self.bot.open(sent)["body"], "retried")

    def test_more_than_100_devices_get_keys_through_bounded_claims(self):
        # A room's members choose how many devices they have; the server claims 100 at most.
        self.env.vouch("u_alice", "bot_helper", self.bot)
        self.env.server.rooms["r1"].append("u_bob")
        alices = [self.alice] + [self.env.person("u_alice") for _ in range(50)]
        bobs = [self.env.person("u_bob") for _ in range(50)]
        sent = self.bot.send("r1", "to everyone")
        self.assertEqual(sorted(self.env.server.claims), [1, 100])
        for d in (alices[0], alices[-1], bobs[0], bobs[-1]):
            d.sync()
            self.assertEqual(d.open(sent)["body"], "to everyone")

    def test_a_device_whose_signed_key_the_core_refuses_is_skipped_alone(self):
        self.env.vouch("u_alice", "bot_helper", self.bot)
        self.env.server.rooms["r1"].append("u_bob")
        bob = self.env.person("u_bob")
        zero = kybot.b64(bytes(32))  # non-contributory: vodozemac refuses a session with it
        self.env.server.otks[("u_bob", bob.device_id)] = [{"key_id": "AAAAAAAAAAA", "key": zero,
            "signature": bob.account().sign(kybot.otk_signed("u_bob", bob.device_id, "AAAAAAAAAAA", zero)).to_base64()}]
        sent = self.bot.send("r1", "still sent")
        self.alice.sync()
        self.assertEqual(self.alice.open(sent)["body"], "still sent")
        self.assertEqual(self.env.mail_to(bob), 0)

    def test_one_time_keys_survive_a_lost_upload_response(self):
        # The server stores the bot's new keys, then the response (or the process) is lost.
        self.env.vouch("u_alice", "bot_helper", self.bot)
        self.env.server.otks[("bot_helper", self.bot.device_id)] = []
        self.env.server.lose_upload = 1
        with self.assertRaises(SystemExit):
            self.bot.sync()
        self.assertEqual(len(self.env.server.otks[("bot_helper", self.bot.device_id)]), kybot.OTK_TARGET)
        sent = self.alice.send("r1", "to a published key")  # claims one of those keys
        restarted = kybot.Bot(self.env.server.as_("bot_helper"), kybot.State(self.bot.st.path))
        restarted.sync()
        self.assertEqual(restarted.open(sent)["body"], "to a published key")

    def test_drained_one_time_keys_leave_the_fallback_key(self):
        self.env.vouch("u_alice", "bot_helper", self.bot)
        for _ in range(kybot.OTK_TARGET):  # anyone in the org can claim them all
            self.env.server.handle("u_mallory", "POST", "/api/v1/keys/claim", {"devices": [{"user_id": "bot_helper", "device_id": self.bot.device_id}]}, None)
        sent = self.alice.send("r1", "through the fallback key")
        self.bot.sync()
        self.assertEqual(self.bot.open(sent)["body"], "through the fallback key")
        # A fallback key the server retired (a restore) is replaced on the next sync.
        k = ("bot_helper", self.bot.device_id)
        old = self.env.server.fallbacks.pop(k)
        self.bot.sync()
        self.assertNotEqual(self.env.server.fallbacks[k]["key"], old["key"])

    def test_an_oversized_message_is_refused_before_any_key_moves(self):
        self.env.vouch("u_alice", "bot_helper", self.bot)
        for text in ("a" * ((16 << 10) + 1), "\x01" * (16 << 10)):  # too long; under 16 KiB but escapes to over 32 KiB
            with self.assertRaises(SystemExit):
                self.bot.send("r1", text)
        self.assertEqual((self.env.mail_to(self.alice), self.env.server.claims, self.env.server.messages), (0, [], {}))
        self.assertEqual(self.bot.send("r1", "\u00e9" * (8 << 10))["room_id"], "r1")  # 16 KiB of UTF-8 still goes
        with self.assertRaises(SystemExit) as cm:  # the server's page limit, as a usage error
            kybot.main(["read", "r1", "--limit", "101"])
        self.assertEqual(cm.exception.code, 2)

    def test_the_bot_reads_its_own_messages(self):
        self.env.vouch("u_alice", "bot_helper", self.bot)
        sent = self.bot.send("r1", "my own words")
        self.assertEqual([m["body"] for m in self.bot.read("r1", 10) if m["id"] == sent["id"]], ["my own words"])

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


class Locking(unittest.TestCase):
    def test_one_command_at_a_time_per_state_file(self):
        import fcntl
        import threading
        d = tempfile.mkdtemp()
        state = os.path.join(d, "s.json")
        held = os.open(state + ".lock", os.O_WRONLY | os.O_CREAT, 0o600)
        fcntl.flock(held, fcntl.LOCK_EX)
        env = {"KYMESSAGES_SERVER_URL": "http://127.0.0.1:9", "KYMESSAGES_ACCESS_TOKEN": "kybot_x"}
        old = {k: os.environ.get(k) for k in env}
        os.environ.update(env)
        done = threading.Event()

        def run():
            try:
                kybot.main(["--state", state, "sync"])
            except BaseException:
                pass
            done.set()
        t = threading.Thread(target=run, daemon=True)
        t.start()
        try:
            self.assertFalse(done.wait(0.5), "a second command ran while the state was locked")
            fcntl.flock(held, fcntl.LOCK_UN)
            self.assertTrue(done.wait(10))
        finally:
            os.close(held)
            for k, v in old.items():
                os.environ.pop(k) if v is None else os.environ.__setitem__(k, v)
            shutil.rmtree(d)


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
