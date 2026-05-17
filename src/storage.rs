use gloo_storage::{LocalStorage, Storage as _};

use crate::types::{NostrAuthError, PersistedMethod, PersistedSession};

/// Persist a session to localStorage. Never writes private key bytes.
pub fn save_session(key: &str, session: &PersistedSession) {
    let json = match serde_json::to_string(session) {
        Ok(s) => s,
        Err(e) => {
            web_sys::console::warn_1(
                &format!("leptos-nostr-auth: failed to serialize session: {e}").into(),
            );
            return;
        }
    };
    if let Err(e) = LocalStorage::set(key, json) {
        web_sys::console::warn_1(
            &format!("leptos-nostr-auth: failed to write localStorage: {e:?}").into(),
        );
    }
}

/// Load a previously saved session from localStorage.
pub fn load_session(key: &str) -> Option<PersistedSession> {
    LocalStorage::get::<String>(key)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
}

/// Remove the stored session.
pub fn clear_session(key: &str) {
    LocalStorage::delete(key);
}

/// Attempt to restore a full `AuthResult` from a `PersistedSession`.
///
/// Each method has different restore semantics:
/// - Extension: verify window.nostr still returns the same pubkey
/// - Bunker: re-establish WebSocket connection using stored bunker URI
/// - Passkey: call navigator.credentials.get() → PRF → rederive key
/// - ReadOnly: restore directly from hex pubkey (no re-auth needed)
pub async fn restore_session(
    session: &PersistedSession,
) -> Result<crate::signers::AuthResult, NostrAuthError> {
    use nostr::PublicKey;

    let stored_pk = PublicKey::from_hex(&session.public_key_hex)
        .map_err(|e| NostrAuthError::InvalidPublicKey(e.to_string()))?;

    match session.method {
        PersistedMethod::Extension => {
            let handle = crate::signers::Nip07Handle::get_public_key().await?;
            if handle.public_key != stored_pk {
                return Err(NostrAuthError::ExtensionRejected(
                    "Extension returned a different public key than the stored session".into(),
                ));
            }
            Ok(crate::signers::AuthResult::Extension(handle))
        }
        PersistedMethod::Bunker => {
            let uri = session
                .bunker_uri
                .as_deref()
                .ok_or_else(|| NostrAuthError::InvalidBunkerUri("no URI stored".into()))?;
            let session = crate::signers::BunkerSession::connect(uri, 30).await?;
            Ok(crate::signers::AuthResult::Bunker(session))
        }
        PersistedMethod::Passkey => {
            let cred_id_b64 = session
                .passkey_credential_id
                .as_deref()
                .ok_or_else(|| NostrAuthError::PasskeyFailed("no credential ID stored".into()))?;
            let cred_id = base64::Engine::decode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                cred_id_b64,
            )
            .map_err(|e| NostrAuthError::PasskeyFailed(e.to_string()))?;
            let ps = crate::signers::PasskeySession::authenticate(cred_id).await?;
            if ps.public_key != stored_pk {
                return Err(NostrAuthError::PasskeyFailed(
                    "Passkey derived a different public key than the stored session".into(),
                ));
            }
            Ok(crate::signers::AuthResult::Passkey(ps))
        }
        PersistedMethod::ReadOnly => {
            Ok(crate::signers::AuthResult::ReadOnly(
                crate::signers::ReadOnlyHandle { public_key: stored_pk },
            ))
        }
    }
}
