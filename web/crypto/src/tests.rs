use wasm_bindgen_test::wasm_bindgen_test;

use super::*;

const KEY: [u8; 32] = [7; 32];

/// Alice opens an Olm session to Bob from one of his published one-time keys.
fn olm_pair() -> (Account, Account, Session, Session, String) {
    let alice = Account::new();
    let mut bob = Account::new();
    bob.generate_one_time_keys(1);
    let otks: BTreeMap<String, String> = serde_json::from_str(&bob.one_time_keys()).unwrap();
    let otk = otks.values().next().unwrap().clone();
    bob.mark_keys_as_published();
    let mut to_bob = alice.create_outbound_session(&bob.curve25519(), &otk).unwrap();
    let first = to_bob.encrypt("hello bob").unwrap();
    assert_eq!(first.message_type(), 0);
    let mut inbound = bob.create_inbound_session(&alice.curve25519(), &first.ciphertext()).unwrap();
    assert_eq!(inbound.plaintext(), "hello bob");
    let from_alice = inbound.take_session().unwrap();
    assert!(inbound.take_session().is_err());
    (alice, bob, to_bob, from_alice, first.ciphertext())
}

#[wasm_bindgen_test]
fn olm_round_trip_and_one_time_key_is_spent() {
    let (alice, mut bob, mut to_bob, mut from_alice, first) = olm_pair();
    assert_eq!(to_bob.session_id(), from_alice.session_id());
    let reply = from_alice.encrypt("hi alice").unwrap();
    assert_eq!(to_bob.decrypt(reply.message_type(), &reply.ciphertext()).unwrap(), "hi alice");
    let next = to_bob.encrypt("second").unwrap();
    assert_eq!(next.message_type(), 1);
    assert_eq!(from_alice.decrypt(1, &next.ciphertext()).unwrap(), "second");

    // Replaying the first pre-key message cannot open a second session: its one-time key is gone.
    assert!(bob.create_inbound_session(&alice.curve25519(), &first).is_err());
}

#[wasm_bindgen_test]
fn olm_refuses_tampered_and_wrong_sender() {
    let (_alice, mut bob, mut to_bob, mut from_alice, _) = olm_pair();
    let m = to_bob.encrypt("secret").unwrap();
    let mut raw = base64_decode(m.ciphertext()).unwrap();
    let last = raw.len() - 1;
    raw[last] ^= 1;
    assert!(from_alice.decrypt(1, &base64_encode(raw)).is_err());
    // A pre-key message claiming another identity key is refused.
    let mallory = Account::new();
    bob.generate_one_time_keys(1);
    let otks: BTreeMap<String, String> = serde_json::from_str(&bob.one_time_keys()).unwrap();
    let mut s = mallory.create_outbound_session(&bob.curve25519(), otks.values().next().unwrap()).unwrap();
    let first = s.encrypt("spoof").unwrap();
    assert!(bob.create_inbound_session(&Account::new().curve25519(), &first.ciphertext()).is_err());
}

#[wasm_bindgen_test]
fn megolm_round_trip_index_and_tamper() {
    let mut out = GroupSession::new();
    let mut inbound = InboundGroupSession::new(&out.session_key()).unwrap();
    assert_eq!(out.session_id(), inbound.session_id());
    let c0 = out.encrypt("one");
    let c1 = out.encrypt("two");
    let d1 = inbound.decrypt(&c1).unwrap();
    assert_eq!((d1.plaintext().as_str(), d1.message_index()), ("two", 1));
    assert_eq!(inbound.decrypt(&c0).unwrap().message_index(), 0);

    // A late joiner given the key at index 2 cannot read earlier messages.
    let mut late = InboundGroupSession::new(&out.session_key()).unwrap();
    assert_eq!(late.first_known_index(), 2);
    assert!(late.decrypt(&c0).is_err());
    assert_eq!(late.decrypt(&out.encrypt("three")).unwrap().plaintext(), "three");

    // Another session's key cannot read this one.
    let mut other = InboundGroupSession::new(&GroupSession::new().session_key()).unwrap();
    assert!(other.decrypt(&c0).is_err());

    let mut raw = base64_decode(&c0).unwrap();
    raw[10] ^= 1;
    assert!(inbound.decrypt(&base64_encode(raw)).is_err());
}

#[wasm_bindgen_test]
fn exported_megolm_key_restores_history() {
    let mut out = GroupSession::new();
    let inbound = InboundGroupSession::new(&out.session_key()).unwrap();
    let c = out.encrypt("backed up");
    let mut restored = InboundGroupSession::import(&inbound.export_at_first_known_index()).unwrap();
    assert_eq!(restored.decrypt(&c).unwrap().plaintext(), "backed up");
}

#[wasm_bindgen_test]
fn pickles_round_trip_only_under_their_key() {
    let mut acct = Account::new();
    acct.generate_one_time_keys(3);
    acct.generate_fallback_key();
    let p = acct.pickle(&KEY).unwrap();
    let back = Account::from_pickle(&p, &KEY).unwrap();
    assert_eq!(back.curve25519(), acct.curve25519());
    assert_eq!(back.one_time_keys(), acct.one_time_keys());
    assert!(Account::from_pickle(&p, &[8; 32]).is_err());
    assert!(acct.pickle(&[1; 31]).is_err());

    let (_a, _b, s, _, _) = olm_pair();
    assert_eq!(Session::from_pickle(&s.pickle(&KEY).unwrap(), &KEY).unwrap().session_id(), s.session_id());
    let g = GroupSession::new();
    assert_eq!(GroupSession::from_pickle(&g.pickle(&KEY).unwrap(), &KEY).unwrap().session_id(), g.session_id());
    let i = InboundGroupSession::new(&g.session_key()).unwrap();
    assert_eq!(InboundGroupSession::from_pickle(&i.pickle(&KEY).unwrap(), &KEY).unwrap().session_id(), i.session_id());
}

#[wasm_bindgen_test]
fn signatures_and_fallback_key() {
    let mut acct = Account::new();
    let sig = acct.sign("device keys");
    assert!(verify_ed25519(&acct.ed25519(), "device keys", &sig));
    assert!(!verify_ed25519(&acct.ed25519(), "device keyz", &sig));
    assert!(!verify_ed25519(&Account::new().ed25519(), "device keys", &sig));
    assert!(!verify_ed25519("not base64!", "device keys", &sig));
    assert_eq!(acct.fallback_key(), "{}");
    acct.generate_fallback_key();
    assert_ne!(acct.fallback_key(), "{}");
    acct.mark_keys_as_published();
    assert_eq!(acct.fallback_key(), "{}");
    assert!(acct.max_one_time_keys() >= 50);
}
