// The browser's crypto core (web/crypto, built to web/src/crypto/pkg) for test_kybot.py: run
// from web/. "keys" makes an account with one one-time key; "open" takes the Python side's Olm
// pre-key message and Megolm message, opens both, and answers with a Megolm message of its own.
import { readFileSync } from 'node:fs';
import * as core from '../../web/src/crypto/pkg/kycrypto.js';

core.initSync({ module: readFileSync('src/crypto/pkg/kycrypto_bg.wasm') });
const key = new Uint8Array(32);
const [cmd, ...a] = process.argv.slice(2);
if (cmd === 'keys') {
  const acct = new core.Account();
  acct.generateOneTimeKeys(1);
  const otk = Object.values(JSON.parse(acct.oneTimeKeys()))[0];
  acct.markKeysAsPublished();
  console.log(JSON.stringify({ curve25519: acct.curve25519, otk, pickle: acct.pickle(key) }));
} else if (cmd === 'open') {
  const [pickle, sender, type, olm, megolm] = a;
  const acct = core.Account.fromPickle(pickle, key);
  if (type !== '0') throw new Error('expected a pre-key message');
  const inbound = acct.createInboundSession(sender, olm);
  const { session_key } = JSON.parse(inbound.plaintext);
  const ig = new core.InboundGroupSession(session_key);
  const opened = ig.decrypt(megolm).plaintext;
  const g = new core.GroupSession();
  const sk = g.sessionKey();
  console.log(JSON.stringify({ megolm: opened, session_key: sk, reply: g.encrypt('hello from a browser') }));
}
