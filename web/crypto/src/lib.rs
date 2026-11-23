//! KyMessages end-to-end encryption core: a thin wasm-bindgen wrapper over vodozemac's Olm and
//! Megolm (docs/superpowers/specs/2026-11-22-e2ee-design.md). Keys, ciphertexts and signatures
//! cross the boundary as unpadded base64 strings; pickles are encrypted under a 32-byte key the
//! caller holds. Nothing here talks to the network or stores anything.

use std::collections::BTreeMap;

use vodozemac::megolm::{
    ExportedSessionKey, GroupSession as VGroupSession, GroupSessionPickle,
    InboundGroupSession as VInboundGroupSession, InboundGroupSessionPickle, MegolmMessage,
    SessionConfig as MegolmConfig, SessionKey,
};
use vodozemac::olm::{
    Account as VAccount, AccountPickle, OlmMessage, Session as VSession, SessionConfig as OlmConfig,
    SessionPickle,
};
use vodozemac::{Curve25519PublicKey, Ed25519PublicKey, Ed25519Signature, base64_decode, base64_encode};
use wasm_bindgen::prelude::*;

fn err(e: impl std::fmt::Display) -> JsError {
    JsError::new(&e.to_string())
}

fn pickle_key(key: &[u8]) -> Result<&[u8; 32], JsError> {
    key.try_into().map_err(|_| JsError::new("pickle key must be 32 bytes"))
}

fn curve(key: &str) -> Result<Curve25519PublicKey, JsError> {
    Curve25519PublicKey::from_base64(key).map_err(err)
}

fn keys_json(keys: impl IntoIterator<Item = (String, Curve25519PublicKey)>) -> String {
    let map: BTreeMap<String, String> = keys.into_iter().map(|(id, k)| (id, k.to_base64())).collect();
    serde_json::to_string(&map).expect("a string map always serializes")
}

/// Verifies an Ed25519 signature over message by key.
#[wasm_bindgen(js_name = verifyEd25519)]
pub fn verify_ed25519(key: &str, message: &str, signature: &str) -> bool {
    match (Ed25519PublicKey::from_base64(key), Ed25519Signature::from_base64(signature)) {
        (Ok(k), Ok(s)) => k.verify(message.as_bytes(), &s).is_ok(),
        _ => false,
    }
}

/// One device's long-term keys (vodozemac `Account`).
#[wasm_bindgen]
pub struct Account {
    inner: VAccount,
}

#[wasm_bindgen]
impl Account {
    #[wasm_bindgen(constructor)]
    #[allow(clippy::new_without_default)]
    pub fn new() -> Account {
        Account { inner: VAccount::new() }
    }

    #[wasm_bindgen(js_name = fromPickle)]
    pub fn from_pickle(pickle: &str, key: &[u8]) -> Result<Account, JsError> {
        let p = AccountPickle::from_encrypted(pickle, pickle_key(key)?).map_err(err)?;
        Ok(Account { inner: VAccount::from_pickle(p) })
    }

    pub fn pickle(&self, key: &[u8]) -> Result<String, JsError> {
        Ok(self.inner.pickle().encrypt(pickle_key(key)?))
    }

    #[wasm_bindgen(getter)]
    pub fn ed25519(&self) -> String {
        self.inner.ed25519_key().to_base64()
    }

    #[wasm_bindgen(getter)]
    pub fn curve25519(&self) -> String {
        self.inner.curve25519_key().to_base64()
    }

    pub fn sign(&self, message: &str) -> String {
        self.inner.sign(message).to_base64()
    }

    #[wasm_bindgen(js_name = maxOneTimeKeys)]
    pub fn max_one_time_keys(&self) -> usize {
        self.inner.max_number_of_one_time_keys()
    }

    #[wasm_bindgen(js_name = generateOneTimeKeys)]
    pub fn generate_one_time_keys(&mut self, count: usize) {
        self.inner.generate_one_time_keys(count);
    }

    /// Unpublished one-time keys as JSON `{key_id: curve25519}`.
    #[wasm_bindgen(js_name = oneTimeKeys)]
    pub fn one_time_keys(&self) -> String {
        keys_json(self.inner.one_time_keys().into_iter().map(|(id, k)| (id.to_base64(), k)))
    }

    #[wasm_bindgen(js_name = generateFallbackKey)]
    pub fn generate_fallback_key(&mut self) {
        self.inner.generate_fallback_key();
    }

    /// The unpublished fallback key as JSON `{key_id: curve25519}` (empty once published).
    #[wasm_bindgen(js_name = fallbackKey)]
    pub fn fallback_key(&self) -> String {
        keys_json(self.inner.fallback_key().into_iter().map(|(id, k)| (id.to_base64(), k)))
    }

    #[wasm_bindgen(js_name = markKeysAsPublished)]
    pub fn mark_keys_as_published(&mut self) {
        self.inner.mark_keys_as_published();
    }

    #[wasm_bindgen(js_name = createOutboundSession)]
    pub fn create_outbound_session(&self, identity_key: &str, one_time_key: &str) -> Result<Session, JsError> {
        let s = self
            .inner
            .create_outbound_session(OlmConfig::version_1(), curve(identity_key)?, curve(one_time_key)?)
            .map_err(err)?;
        Ok(Session { inner: s })
    }

    /// Starts a session from a peer's first (pre-key, type 0) message and returns it with the
    /// message's plaintext. Consumes the one-time key it used.
    #[wasm_bindgen(js_name = createInboundSession)]
    pub fn create_inbound_session(&mut self, identity_key: &str, ciphertext: &str) -> Result<InboundSession, JsError> {
        let bytes = base64_decode(ciphertext).map_err(err)?;
        let OlmMessage::PreKey(m) = OlmMessage::from_parts(0, &bytes).map_err(err)? else {
            return Err(JsError::new("not a pre-key message"));
        };
        let r = self
            .inner
            .create_inbound_session(OlmConfig::version_1(), curve(identity_key)?, &m)
            .map_err(err)?;
        let plaintext = String::from_utf8(r.plaintext).map_err(err)?;
        Ok(InboundSession { session: Some(Session { inner: r.session }), plaintext })
    }
}

/// The result of `Account.createInboundSession`.
#[wasm_bindgen]
pub struct InboundSession {
    session: Option<Session>,
    plaintext: String,
}

#[wasm_bindgen]
impl InboundSession {
    /// The new session; can be taken once.
    #[wasm_bindgen(js_name = takeSession)]
    pub fn take_session(&mut self) -> Result<Session, JsError> {
        self.session.take().ok_or_else(|| JsError::new("session already taken"))
    }

    #[wasm_bindgen(getter)]
    pub fn plaintext(&self) -> String {
        self.plaintext.clone()
    }
}

/// An encrypted Olm message: `type` 0 is a pre-key message, 1 a normal one.
#[wasm_bindgen]
pub struct EncryptedOlm {
    message_type: usize,
    ciphertext: String,
}

#[wasm_bindgen]
impl EncryptedOlm {
    #[wasm_bindgen(getter, js_name = type)]
    pub fn message_type(&self) -> usize {
        self.message_type
    }

    #[wasm_bindgen(getter)]
    pub fn ciphertext(&self) -> String {
        self.ciphertext.clone()
    }
}

/// A pairwise Olm session between two devices.
#[wasm_bindgen]
pub struct Session {
    inner: VSession,
}

#[wasm_bindgen]
impl Session {
    #[wasm_bindgen(js_name = fromPickle)]
    pub fn from_pickle(pickle: &str, key: &[u8]) -> Result<Session, JsError> {
        let p = SessionPickle::from_encrypted(pickle, pickle_key(key)?).map_err(err)?;
        Ok(Session { inner: VSession::from_pickle(p) })
    }

    pub fn pickle(&self, key: &[u8]) -> Result<String, JsError> {
        Ok(self.inner.pickle().encrypt(pickle_key(key)?))
    }

    #[wasm_bindgen(getter, js_name = sessionId)]
    pub fn session_id(&self) -> String {
        self.inner.session_id()
    }

    pub fn encrypt(&mut self, plaintext: &str) -> Result<EncryptedOlm, JsError> {
        let (t, bytes) = self.inner.encrypt(plaintext).map_err(err)?.to_parts();
        Ok(EncryptedOlm { message_type: t, ciphertext: base64_encode(bytes) })
    }

    pub fn decrypt(&mut self, message_type: usize, ciphertext: &str) -> Result<String, JsError> {
        let bytes = base64_decode(ciphertext).map_err(err)?;
        let m = OlmMessage::from_parts(message_type, &bytes).map_err(err)?;
        String::from_utf8(self.inner.decrypt(&m).map_err(err)?).map_err(err)
    }
}

/// The sending half of a room's Megolm session.
#[wasm_bindgen]
pub struct GroupSession {
    inner: VGroupSession,
}

#[wasm_bindgen]
impl GroupSession {
    #[wasm_bindgen(constructor)]
    #[allow(clippy::new_without_default)]
    pub fn new() -> GroupSession {
        GroupSession { inner: VGroupSession::new(MegolmConfig::version_1()) }
    }

    #[wasm_bindgen(js_name = fromPickle)]
    pub fn from_pickle(pickle: &str, key: &[u8]) -> Result<GroupSession, JsError> {
        let p = GroupSessionPickle::from_encrypted(pickle, pickle_key(key)?).map_err(err)?;
        Ok(GroupSession { inner: VGroupSession::from_pickle(p) })
    }

    pub fn pickle(&self, key: &[u8]) -> Result<String, JsError> {
        Ok(self.inner.pickle().encrypt(pickle_key(key)?))
    }

    #[wasm_bindgen(getter, js_name = sessionId)]
    pub fn session_id(&self) -> String {
        self.inner.session_id()
    }

    #[wasm_bindgen(getter, js_name = messageIndex)]
    pub fn message_index(&self) -> u32 {
        self.inner.message_index()
    }

    /// The key that lets a recipient decrypt from the current index on. Send it only over Olm.
    #[wasm_bindgen(js_name = sessionKey)]
    pub fn session_key(&self) -> String {
        self.inner.session_key().to_base64()
    }

    pub fn encrypt(&mut self, plaintext: &str) -> String {
        self.inner.encrypt(plaintext).to_base64()
    }
}

/// A decrypted Megolm message and its ratchet index (for replay detection).
#[wasm_bindgen]
pub struct DecryptedGroup {
    plaintext: String,
    message_index: u32,
}

#[wasm_bindgen]
impl DecryptedGroup {
    #[wasm_bindgen(getter)]
    pub fn plaintext(&self) -> String {
        self.plaintext.clone()
    }

    #[wasm_bindgen(getter, js_name = messageIndex)]
    pub fn message_index(&self) -> u32 {
        self.message_index
    }
}

/// The receiving half of a room's Megolm session.
#[wasm_bindgen]
pub struct InboundGroupSession {
    inner: VInboundGroupSession,
}

#[wasm_bindgen]
impl InboundGroupSession {
    /// From a `GroupSession.sessionKey()` received over Olm (it is signed by the sender).
    #[wasm_bindgen(constructor)]
    pub fn new(session_key: &str) -> Result<InboundGroupSession, JsError> {
        let key = SessionKey::from_base64(session_key).map_err(err)?;
        Ok(InboundGroupSession { inner: VInboundGroupSession::new(&key, MegolmConfig::version_1()) })
    }

    /// From an unsigned export (the key backup); trust comes from the backup, not the key.
    pub fn import(exported_key: &str) -> Result<InboundGroupSession, JsError> {
        let key = ExportedSessionKey::from_base64(exported_key).map_err(err)?;
        Ok(InboundGroupSession { inner: VInboundGroupSession::import(&key, MegolmConfig::version_1()) })
    }

    #[wasm_bindgen(js_name = fromPickle)]
    pub fn from_pickle(pickle: &str, key: &[u8]) -> Result<InboundGroupSession, JsError> {
        let p = InboundGroupSessionPickle::from_encrypted(pickle, pickle_key(key)?).map_err(err)?;
        Ok(InboundGroupSession { inner: VInboundGroupSession::from_pickle(p) })
    }

    pub fn pickle(&self, key: &[u8]) -> Result<String, JsError> {
        Ok(self.inner.pickle().encrypt(pickle_key(key)?))
    }

    #[wasm_bindgen(getter, js_name = sessionId)]
    pub fn session_id(&self) -> String {
        self.inner.session_id()
    }

    #[wasm_bindgen(getter, js_name = firstKnownIndex)]
    pub fn first_known_index(&self) -> u32 {
        self.inner.first_known_index()
    }

    /// Exports the session from its first known index, for the key backup.
    #[wasm_bindgen(js_name = exportAtFirstKnownIndex)]
    pub fn export_at_first_known_index(&self) -> String {
        self.inner.export_at_first_known_index().to_base64()
    }

    pub fn decrypt(&mut self, ciphertext: &str) -> Result<DecryptedGroup, JsError> {
        let m = MegolmMessage::from_base64(ciphertext).map_err(err)?;
        let d = self.inner.decrypt(&m).map_err(err)?;
        Ok(DecryptedGroup { plaintext: String::from_utf8(d.plaintext).map_err(err)?, message_index: d.message_index })
    }
}

#[cfg(test)]
mod tests;
