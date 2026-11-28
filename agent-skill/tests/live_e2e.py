"""kybot.py against a real KyMessages server (not run in CI's unit step).

    KYBOT_LIVE_URL=http://127.0.0.1:18093 KYBOT_LIVE_ADMIN_PASSWORD=... python3 -B agent-skill/tests/live_e2e.py

The bootstrap admin plays the bot's owner: it sets an E3 identity with a test master key, signs
and lists its own device, creates the bot, vouches for the bot's device and talks with it.
"""
import json
import os
import secrets
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "kymessages" / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import kybot  # noqa: E402
from test_kybot import Master  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import mlkem, x25519  # noqa: E402

URL, PASS = os.environ["KYBOT_LIVE_URL"], os.environ["KYBOT_LIVE_ADMIN_PASSWORD"]


def login(user, password):
    req = urllib.request.Request(URL + "/api/auth/login", data=json.dumps({"username": user, "password": password}).encode(), method="POST", headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req) as r:
        body = json.loads(r.read())
        cookies = r.headers.get_all("Set-Cookie")
    tok = next(c.split("=", 1)[1].split(";", 1)[0] for c in cookies if "ky_session=" in c)
    return tok, body


def expect_refused(srv, method, path, body, code):
    try:
        srv.call(method, path, body)
    except SystemExit as e:
        assert f"HTTP {code}" in str(e), e
        return
    raise AssertionError(f"{method} {path} was accepted")


tok, body = login("admin", PASS)
admin = kybot.Server(URL, tok)
me = admin.call("GET", "/api/auth/me")["user"]
if me.get("must_change_password"):
    new = "Live" + secrets.token_hex(8) + "!"
    admin.call("POST", "/api/auth/change-password", {"current_password": PASS, "new_password": new})
    tok, _ = login("admin", new)
    admin = kybot.Server(URL, tok)
uid = me["id"]
tenant = admin.call("GET", "/api/v1/keys/master")["tenant_id"]
work = tempfile.mkdtemp()

# The owner's identity (as a browser's E3 setup makes it) and its verified device.
m = Master()
xw = mlkem.MLKEM768PrivateKey.generate().public_key().public_bytes_raw() + x25519.X25519PrivateKey.generate().public_key().public_bytes_raw()
admin.call("PUT", "/api/v1/keys/master", {
    "expected_version": 0, "master_key": m.public, "self_signature": m.sign(kybot.DOMAIN_MASTER, kybot.master_self_msg(tenant, uid, m.public)),
    "backup_key": {"public_key": kybot.b64(xw), "signature": m.sign("kymessages.backup-key.v1", kybot.fields(kybot.ALG.encode(), tenant.encode(), uid.encode(), b"1", xw))},
    "recovery": {"wrapped_master_key": kybot.b64(b"\1" + secrets.token_bytes(92)), "wrapped_backup_key": kybot.b64(b"\1" + secrets.token_bytes(60))}})
owner = kybot.Bot(admin, kybot.State(os.path.join(work, "owner.json")))
owner.init()
dev = next(d for d in admin.call("POST", "/api/v1/keys/query", {"user_ids": [uid]})["devices"][uid] if d["device_id"] == owner.device_id)
admin.call("POST", f"/api/v1/keys/devices/{owner.device_id}/signature", {"version": 1, "signature": m.sign(kybot.DOMAIN_DEVICE, kybot.device_msg(tenant, uid, owner.device_id, dev["curve25519"], dev["ed25519"]))})
ids = [owner.device_id]
digest = kybot.phash("kymessages.device-list", *ids)
r = admin.call("POST", "/api/v1/keys/devices/list/reserve", {"version": 1, "expected_epoch": 0, "digest": digest,
               "signature": m.sign("kymessages.device-list-reserve.v1", kybot.fields(*(v.encode() for v in (kybot.ALG, tenant, uid, "1", "0", digest))))})
admin.call("PUT", "/api/v1/keys/devices/list", {"version": 1, "expected_epoch": 0, "epoch": r["epoch"], "device_ids": ids,
           "signature": m.sign(kybot.DOMAIN_DEVICE_LIST, kybot.device_list_msg(tenant, uid, 1, r["epoch"], ids))})

# The bot: created by the admin for itself, then a device of its own.
created = admin.call("POST", "/api/admin/agents", {"name": "agent-live-" + secrets.token_hex(3), "owner": uid})
bot_srv = kybot.Server(URL, created["token"])
bot = kybot.Bot(bot_srv, kybot.State(os.path.join(work, "bot.json")))
info = bot.init()
room = admin.call("POST", "/api/v1/rooms", {"kind": "channel", "name": "live-" + secrets.token_hex(3), "member_ids": [info["user_id"]]})["room"]["id"]

# Plaintext is refused from the bot, messages and files alike.
expect_refused(bot_srv, "POST", f"/api/v1/rooms/{room}/messages", {"body": "plain"}, 400)

# Before vouching: the owner's device shares nothing with the bot.
owner.send(room, "before vouching")
assert bot.sync() == [], "an unvouched bot got a room key"

# The owner checks the code and vouches (what "Your bots" signs).
view = admin.call("POST", "/api/v1/keys/query", {"user_ids": [info["user_id"]]})["devices"][info["user_id"]]
d = next(x for x in view if x["device_id"] == info["device_id"])
assert kybot.device_code(info["user_id"], d["device_id"], d["curve25519"], d["ed25519"]) == info["code"]
devs = [{k: d[k] for k in ("device_id", "curve25519", "ed25519")}]
admin.call("PUT", f"/api/v1/keys/bots/{info['user_id']}/devices", {"version": 1, "expected_epoch": 0, "epoch": 1, "devices": devs,
           "signature": m.sign(kybot.DOMAIN_BOT_DEVICES, kybot.bot_devices_msg(tenant, uid, 1, info["user_id"], 1, devs))})

sent = bot.send(room, "hello from the bot")
assert owner.sync(), "the owner got no room key from the vouched bot"
assert owner.open(sent)["body"] == "hello from the bot"
del owner.st["outbound"][room]  # the owner's next message, under a session shared now
reply = owner.send(room, "hello bot")
assert bot.sync(), "the vouched bot got no room key"
got = [x for x in bot.read(room, 20) if x["id"] == reply["id"]][0]
assert got["body"] == "hello bot", got

f = os.path.join(work, "report.txt")
Path(f).write_bytes(b"live file\n" * 10000)
withfile = bot.send(room, "a file", file=f)
att = withfile["attachments"][0]["id"]
assert owner.download(room, withfile["id"], att) == Path(f).read_bytes()

# Revoked by the owner: the bot gets no new room key.
admin.call("PUT", f"/api/v1/keys/bots/{info['user_id']}/devices", {"version": 1, "expected_epoch": 1, "epoch": 2, "devices": [],
           "signature": m.sign(kybot.DOMAIN_BOT_DEVICES, kybot.bot_devices_msg(tenant, uid, 1, info["user_id"], 2, []))})
owner.send(room, "after revocation")
assert bot.sync() == [], "a revoked bot got a room key"

# Vouched again; the owner sends, then signs out (delists, then deletes its device) before the
# bot syncs: the mail kept the device's cross-signature, so the bot still reads the message.
admin.call("PUT", f"/api/v1/keys/bots/{info['user_id']}/devices", {"version": 1, "expected_epoch": 2, "epoch": 3, "devices": devs,
           "signature": m.sign(kybot.DOMAIN_BOT_DEVICES, kybot.bot_devices_msg(tenant, uid, 1, info["user_id"], 3, devs))})
late = owner.send(room, "sent before sign-out")
digest = kybot.phash("kymessages.device-list")
r2 = admin.call("POST", "/api/v1/keys/devices/list/reserve", {"version": 1, "expected_epoch": r["epoch"], "digest": digest,
                "signature": m.sign("kymessages.device-list-reserve.v1", kybot.fields(*(v.encode() for v in (kybot.ALG, tenant, uid, "1", str(r["epoch"]), digest))))})
admin.call("PUT", "/api/v1/keys/devices/list", {"version": 1, "expected_epoch": r["epoch"], "epoch": r2["epoch"], "device_ids": [],
           "signature": m.sign(kybot.DOMAIN_DEVICE_LIST, kybot.device_list_msg(tenant, uid, 1, r2["epoch"], []))})
admin.call("DELETE", f"/api/v1/keys/devices/{owner.device_id}")
assert bot.sync(), "the bot dropped a room key from a device that signed out"
got = [x for x in bot.read(room, 20) if x["id"] == late["id"]][0]
assert got.get("body") == "sent before sign-out", got
print("live e2e: all checks passed")
