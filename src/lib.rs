//! Leptos Nostr Auth — headless Nostr login modal widget for Leptos applications.
//!
//! # Quick start
//!
//! ```rust,ignore
//! // Wrap your app root:
//! <NostrAuthProvider>
//!     <App/>
//! </NostrAuthProvider>
//!
//! // Anywhere inside the tree:
//! let auth = use_nostr_auth();
//! view! {
//!     <Show when=move || auth.is_authenticated.get()>
//!         <p>"Logged in as " {move || auth.public_key.get().map(|k| k.to_bech32())}</p>
//!     </Show>
//!     <button on:click=move |_| auth.show_login.run(())>"Login"</button>
//! }
//! ```
//!
//! # Feature flags
//!
//! - `daisyui` — enables daisyUI 5 + Tailwind v4 styling with dark theme
//! - `insecure_nsec_input` — enables raw nsec/hex key paste (XSS risk; opt-in only)

pub mod context;
pub mod modal;
pub mod platform;
pub mod signers;
pub mod storage;

// Public re-exports
pub use context::{use_nostr_auth, NostrAuthContext, NostrAuthProvider};
pub use modal::NostrAuthModal;

// Core types
pub use types::{
    AuthResult, LoginMethod, NostrAuthConfig, NostrAuthError, PersistedMethod, PersistedSession,
};
pub use signers::{BunkerSession, Nip07Handle, PasskeySession, RawKeySession, ReadOnlyHandle};

mod types {
    use nostr::PublicKey;
    use serde::{Deserialize, Serialize};
    use thiserror::Error;

    use crate::signers::{BunkerSession, Nip07Handle, PasskeySession, RawKeySession, ReadOnlyHandle};

    /// Result of a successful authentication attempt.
    /// Owned by this library — not coupled to any specific rust-nostr version.
    #[derive(Clone)]
    pub enum AuthResult {
        /// NIP-07: browser extension (Alby, nos2x, Nostr KeyX, etc.)
        Extension(Nip07Handle),
        /// NIP-46: remote bunker signer (also covers Amber via NIP-46 mode)
        Bunker(BunkerSession),
        /// Passkey: WebAuthn PRF-derived secp256k1 key, syncs via iCloud Keychain / platform
        Passkey(PasskeySession),
        /// Read-only: public key only, no signing capability
        ReadOnly(ReadOnlyHandle),
        /// NIP-49: ncryptsec password-decrypted key (in-memory only)
        Ncryptsec(RawKeySession),
        /// Raw nsec paste: in-memory key (only with `insecure_nsec_input` feature)
        #[cfg(feature = "insecure_nsec_input")]
        RawNsec(RawKeySession),
    }

    impl AuthResult {
        /// Returns the public key for any auth variant.
        pub fn public_key(&self) -> PublicKey {
            match self {
                AuthResult::Extension(h) => h.public_key,
                AuthResult::Bunker(s) => s.public_key,
                AuthResult::Passkey(s) => s.public_key,
                AuthResult::ReadOnly(h) => h.public_key,
                AuthResult::Ncryptsec(s) => s.public_key,
                #[cfg(feature = "insecure_nsec_input")]
                AuthResult::RawNsec(s) => s.public_key,
            }
        }

        /// Build a `PersistedSession` for localStorage (never stores private key bytes).
        pub fn to_persisted_session(&self) -> Option<PersistedSession> {
            match self {
                AuthResult::Extension(h) => Some(PersistedSession {
                    public_key_hex: h.public_key.to_hex(),
                    method: PersistedMethod::Extension,
                    bunker_uri: None,
                    passkey_credential_id: None,
                }),
                AuthResult::Bunker(s) => Some(PersistedSession {
                    public_key_hex: s.public_key.to_hex(),
                    method: PersistedMethod::Bunker,
                    bunker_uri: Some(s.bunker_uri.clone()),
                    passkey_credential_id: None,
                }),
                AuthResult::Passkey(s) => Some(PersistedSession {
                    public_key_hex: s.public_key.to_hex(),
                    method: PersistedMethod::Passkey,
                    bunker_uri: None,
                    passkey_credential_id: Some(base64::Engine::encode(
                        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                        &s.credential_id,
                    )),
                }),
                AuthResult::ReadOnly(h) => Some(PersistedSession {
                    public_key_hex: h.public_key.to_hex(),
                    method: PersistedMethod::ReadOnly,
                    bunker_uri: None,
                    passkey_credential_id: None,
                }),
                // ncryptsec and raw nsec: key is not persisted (no safe way to store it)
                AuthResult::Ncryptsec(_) => None,
                #[cfg(feature = "insecure_nsec_input")]
                AuthResult::RawNsec(_) => None,
            }
        }
    }

    /// What gets written to localStorage — never contains private key material.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct PersistedSession {
        pub public_key_hex: String,
        pub method: PersistedMethod,
        /// NIP-46: stored bunker URI for re-connection on restore
        pub bunker_uri: Option<String>,
        /// Passkey: base64url credential ID — used to call `credentials.get()`
        pub passkey_credential_id: Option<String>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum PersistedMethod {
        Extension,
        Bunker,
        Passkey,
        ReadOnly,
    }

    /// Which login methods to show in the modal.
    #[derive(Clone, PartialEq)]
    pub enum LoginMethod {
        Extension,
        Bunker,
        Passkey,
        ReadOnly,
        Ncryptsec,
        #[cfg(feature = "insecure_nsec_input")]
        RawNsec,
    }

    impl LoginMethod {
        pub fn all() -> Vec<LoginMethod> {
            vec![
                LoginMethod::Extension,
                LoginMethod::Bunker,
                LoginMethod::Passkey,
                LoginMethod::ReadOnly,
                LoginMethod::Ncryptsec,
                #[cfg(feature = "insecure_nsec_input")]
                LoginMethod::RawNsec,
            ]
        }
    }

    /// Configuration for [`NostrAuthModal`] and [`NostrAuthProvider`].
    #[derive(Clone)]
    pub struct NostrAuthConfig {
        /// Persist session to localStorage after login (default: `true`)
        pub persist_session: bool,
        /// localStorage key (default: `"leptos_nostr_auth_session"`)
        pub storage_key: &'static str,
        /// Close modal on backdrop click (default: `true`)
        pub close_on_backdrop_click: bool,
        /// Close modal on Escape key (default: `true`)
        pub close_on_escape: bool,
        /// Which login methods to expose (default: all)
        pub allowed_methods: Vec<LoginMethod>,
        /// NIP-46 WebSocket connection timeout in seconds (default: `30`)
        pub bunker_timeout_secs: u32,
        /// WebAuthn relying party ID — MUST match your domain (default: `window.location.hostname`)
        ///
        /// **Required for passkey to work.** Passkeys are scoped to an RP ID.
        /// Set this to your domain, e.g. `"myapp.com"` (no `https://` prefix).
        pub rp_id: Option<String>,
        /// WebAuthn relying party display name (default: `"Nostr App"`)
        pub rp_name: &'static str,
    }

    impl Default for NostrAuthConfig {
        fn default() -> Self {
            Self {
                persist_session: true,
                storage_key: "leptos_nostr_auth_session",
                close_on_backdrop_click: true,
                close_on_escape: true,
                allowed_methods: LoginMethod::all(),
                bunker_timeout_secs: 30,
                rp_id: None,
                rp_name: "Nostr App",
            }
        }
    }

    /// Errors returned by authentication operations.
    #[derive(Debug, Error, Clone)]
    pub enum NostrAuthError {
        #[error("Browser extension (window.nostr) not found")]
        ExtensionNotFound,
        #[error("Extension request rejected: {0}")]
        ExtensionRejected(String),
        #[error("Invalid public key format: {0}")]
        InvalidPublicKey(String),
        #[error("Invalid bunker URI: {0}")]
        InvalidBunkerUri(String),
        #[error("Bunker connection failed: {0}")]
        BunkerConnectionFailed(String),
        #[error("Bunker connection timed out")]
        BunkerTimeout,
        #[error("Passkey operation failed: {0}")]
        PasskeyFailed(String),
        #[error("Browser does not support WebAuthn PRF extension")]
        PasskeyNotSupported,
        #[error("Invalid ncryptsec string: {0}")]
        InvalidNcryptsec(String),
        #[error("Wrong password for ncryptsec")]
        WrongPassword,
        #[error("Invalid secret key: {0}")]
        InvalidSecretKey(String),
        #[error("Signing failed: {0}")]
        SigningFailed(String),
        #[error("Serialization error: {0}")]
        Serialization(String),
    }
}
