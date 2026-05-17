use std::cell::RefCell;

use base64::Engine as _;
use js_sys::{Array, Object, Promise, Reflect, Uint8Array};
use nostr::{FromBech32, JsonUtil, Keys, PublicKey, SecretKey};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

use crate::types::NostrAuthError;

/// Re-export so storage.rs can use it without circular imports.
pub use crate::types::AuthResult;

// ─────────────────────────────────────────────
//  NIP-07: Browser Extension
// ─────────────────────────────────────────────

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = ["window", "nostr"], js_name = getPublicKey, catch)]
    async fn nostr_get_public_key() -> Result<JsValue, JsValue>;

    #[wasm_bindgen(js_namespace = ["window", "nostr"], js_name = signEvent, catch)]
    async fn nostr_sign_event(event: JsValue) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(js_namespace = ["window", "nostr", "nip44"], js_name = encrypt, catch)]
    async fn nostr_nip44_encrypt(pubkey: &str, plaintext: &str) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(js_namespace = ["window", "nostr", "nip44"], js_name = decrypt, catch)]
    async fn nostr_nip44_decrypt(pubkey: &str, ciphertext: &str) -> Result<JsValue, JsValue>;
}

/// Handle to an authenticated NIP-07 browser extension session.
#[derive(Clone)]
pub struct Nip07Handle {
    pub public_key: PublicKey,
}

impl Nip07Handle {
    /// Request the public key from the browser extension.
    pub async fn get_public_key() -> Result<Self, NostrAuthError> {
        let js_pk = nostr_get_public_key().await.map_err(|e| {
            NostrAuthError::ExtensionRejected(
                e.as_string().unwrap_or_else(|| "unknown error".into()),
            )
        })?;
        let hex = js_pk
            .as_string()
            .ok_or_else(|| NostrAuthError::ExtensionRejected("expected string pubkey".into()))?;
        let pk = PublicKey::from_hex(&hex)
            .map_err(|e| NostrAuthError::InvalidPublicKey(e.to_string()))?;
        Ok(Self { public_key: pk })
    }

    /// Sign a Nostr event via the extension.
    pub async fn sign_event(&self, event_json: &str) -> Result<String, NostrAuthError> {
        let event_val = js_sys::JSON::parse(event_json)
            .map_err(|_| NostrAuthError::SigningFailed("invalid event JSON".into()))?;
        let signed = nostr_sign_event(event_val).await.map_err(|e| {
            NostrAuthError::SigningFailed(e.as_string().unwrap_or_else(|| "rejected".into()))
        })?;
        js_sys::JSON::stringify(&signed)
            .map(|s| s.as_string().unwrap_or_default())
            .map_err(|_| NostrAuthError::SigningFailed("could not stringify signed event".into()))
    }

    /// NIP-44 encrypt via extension.
    pub async fn nip44_encrypt(
        &self,
        recipient_hex: &str,
        plaintext: &str,
    ) -> Result<String, NostrAuthError> {
        nostr_nip44_encrypt(recipient_hex, plaintext)
            .await
            .map_err(|e| {
                NostrAuthError::SigningFailed(
                    e.as_string().unwrap_or_else(|| "encrypt failed".into()),
                )
            })?
            .as_string()
            .ok_or_else(|| NostrAuthError::SigningFailed("expected string ciphertext".into()))
    }

    /// NIP-44 decrypt via extension.
    pub async fn nip44_decrypt(
        &self,
        sender_hex: &str,
        ciphertext: &str,
    ) -> Result<String, NostrAuthError> {
        nostr_nip44_decrypt(sender_hex, ciphertext)
            .await
            .map_err(|e| {
                NostrAuthError::SigningFailed(
                    e.as_string().unwrap_or_else(|| "decrypt failed".into()),
                )
            })?
            .as_string()
            .ok_or_else(|| NostrAuthError::SigningFailed("expected string plaintext".into()))
    }
}

// ─────────────────────────────────────────────
//  NIP-46: Nostr Connect / Bunker
// ─────────────────────────────────────────────

/// Parsed bunker:// URI components.
struct BunkerUri {
    remote_pubkey_hex: String,
    relay_url: String,
    secret: Option<String>,
}

fn parse_bunker_uri(uri: &str) -> Result<BunkerUri, NostrAuthError> {
    // Accept both bunker:// and nostrconnect:// schemes
    let stripped = uri
        .strip_prefix("bunker://")
        .or_else(|| uri.strip_prefix("nostrconnect://"))
        .ok_or_else(|| {
            NostrAuthError::InvalidBunkerUri(
                "URI must start with bunker:// or nostrconnect://".into(),
            )
        })?;

    let (pubkey_part, query) = stripped.split_once('?').unwrap_or((stripped, ""));
    let remote_pubkey_hex = pubkey_part.to_string();

    // Validate it looks like a hex pubkey or npub
    if remote_pubkey_hex.is_empty() {
        return Err(NostrAuthError::InvalidBunkerUri(
            "missing remote pubkey".into(),
        ));
    }

    let mut relay_url = String::new();
    let mut secret = None;

    for pair in query.split('&').filter(|s| !s.is_empty()) {
        if let Some((k, v)) = pair.split_once('=') {
            match k {
                "relay" => relay_url = urlencoding_decode(v),
                "secret" => secret = Some(urlencoding_decode(v)),
                _ => {}
            }
        }
    }

    if relay_url.is_empty() {
        return Err(NostrAuthError::InvalidBunkerUri("missing relay URL".into()));
    }

    Ok(BunkerUri {
        remote_pubkey_hex,
        relay_url,
        secret,
    })
}

fn urlencoding_decode(s: &str) -> String {
    js_sys::decode_uri_component(s).map_or_else(
        |_| s.to_string(),
        |v| v.as_string().unwrap_or_else(|| s.to_string()),
    )
}

/// An established NIP-46 remote signing session.
#[derive(Clone)]
pub struct BunkerSession {
    pub public_key: PublicKey,
    /// Stored for session restore
    pub bunker_uri: String,
    /// Ephemeral client keypair — stays in memory
    client_keys: Keys,
    remote_pubkey: PublicKey,
    relay_url: String,
}

impl BunkerSession {
    /// Establish a NIP-46 connection from a `bunker://` or `nostrconnect://` URI.
    pub async fn connect(uri: &str, timeout_secs: u32) -> Result<Self, NostrAuthError> {
        let parsed = parse_bunker_uri(uri)?;

        let remote_pubkey = PublicKey::from_hex(&parsed.remote_pubkey_hex)
            .map_err(|e| NostrAuthError::InvalidPublicKey(e.to_string()))?;

        // Generate an ephemeral keypair for this client session
        let client_keys = Keys::generate();
        let client_pubkey_hex = client_keys.public_key().to_hex();

        // NIP-46 connect request payload
        let req_id = generate_request_id();
        let params = match &parsed.secret {
            Some(s) => serde_json::json!({
                "id": req_id,
                "method": "connect",
                "params": [client_pubkey_hex, s, "sign_event,get_public_key,nip44_encrypt,nip44_decrypt"]
            }),
            None => serde_json::json!({
                "id": req_id,
                "method": "connect",
                "params": [client_pubkey_hex, "", "sign_event,get_public_key,nip44_encrypt,nip44_decrypt"]
            }),
        };

        let req_json = serde_json::to_string(&params)
            .map_err(|e| NostrAuthError::Serialization(e.to_string()))?;

        // Encrypt request with NIP-44 using client secret key
        let encrypted = nostr::nips::nip44::encrypt(
            client_keys.secret_key(),
            &remote_pubkey,
            &req_json,
            nostr::nips::nip44::Version::V2,
        )
        .map_err(|e| NostrAuthError::BunkerConnectionFailed(e.to_string()))?;

        // Build a kind:24133 event signed by client ephemeral key
        let event = nostr::EventBuilder::new(nostr::Kind::Custom(24133), encrypted)
            .tag(nostr::Tag::public_key(remote_pubkey))
            .sign_with_keys(&client_keys)
            .map_err(|e| NostrAuthError::BunkerConnectionFailed(e.to_string()))?;

        let event_json = event.as_json();

        // Open WebSocket and do the handshake
        let remote_pubkey_hex = parsed.remote_pubkey_hex.clone();
        let relay_url = parsed.relay_url.clone();

        let result_pubkey = websocket_bunker_handshake(
            &relay_url,
            &event_json,
            &client_pubkey_hex,
            &remote_pubkey_hex,
            &client_keys,
            &req_id,
            timeout_secs,
        )
        .await?;

        Ok(Self {
            public_key: result_pubkey,
            bunker_uri: uri.to_string(),
            client_keys,
            remote_pubkey,
            relay_url: parsed.relay_url,
        })
    }

    /// Send a NIP-46 sign_event request to the remote signer.
    pub async fn sign_event(&self, event_json: &str) -> Result<String, NostrAuthError> {
        let req_id = generate_request_id();
        let req = serde_json::json!({
            "id": req_id,
            "method": "sign_event",
            "params": [serde_json::from_str::<serde_json::Value>(event_json)
                .map_err(|e| NostrAuthError::Serialization(e.to_string()))?]
        });
        let req_json = serde_json::to_string(&req)
            .map_err(|e| NostrAuthError::Serialization(e.to_string()))?;

        let encrypted = nostr::nips::nip44::encrypt(
            self.client_keys.secret_key(),
            &self.remote_pubkey,
            &req_json,
            nostr::nips::nip44::Version::V2,
        )
        .map_err(|e| NostrAuthError::SigningFailed(e.to_string()))?;

        let event = nostr::EventBuilder::new(nostr::Kind::Custom(24133), encrypted)
            .tag(nostr::Tag::public_key(self.remote_pubkey))
            .sign_with_keys(&self.client_keys)
            .map_err(|e| NostrAuthError::SigningFailed(e.to_string()))?;

        // Re-open a short-lived WebSocket connection for signing
        let response = websocket_rpc_call(
            &self.relay_url,
            &event.as_json(),
            &self.client_keys.public_key().to_hex(),
            &self.remote_pubkey.to_hex(),
            &self.client_keys,
            &req_id,
            30,
        )
        .await?;
        Ok(response)
    }
}

/// Performs the NIP-46 connect handshake over WebSocket and returns the remote pubkey.
async fn websocket_bunker_handshake(
    relay_url: &str,
    event_json: &str,
    client_pubkey_hex: &str,
    remote_pubkey_hex: &str,
    client_keys: &Keys,
    req_id: &str,
    timeout_secs: u32,
) -> Result<PublicKey, NostrAuthError> {
    let result = websocket_rpc_call(
        relay_url,
        event_json,
        client_pubkey_hex,
        remote_pubkey_hex,
        client_keys,
        req_id,
        timeout_secs,
    )
    .await?;

    // "ack" or the remote pubkey hex is acceptable as a connect response
    let response: serde_json::Value = serde_json::from_str(&result)
        .map_err(|e| NostrAuthError::BunkerConnectionFailed(e.to_string()))?;

    let pk_hex = response
        .as_str()
        .or_else(|| response["result"].as_str())
        .unwrap_or_default();

    if pk_hex == "ack" || pk_hex.is_empty() {
        // Some bunkers ack without returning the pubkey — do a get_public_key call
        return get_bunker_public_key(relay_url, client_pubkey_hex, remote_pubkey_hex, client_keys)
            .await;
    }

    PublicKey::from_hex(pk_hex).map_err(|e| NostrAuthError::InvalidPublicKey(e.to_string()))
}

/// Minimal get_public_key RPC call to retrieve the remote signer's pubkey after connect.
async fn get_bunker_public_key(
    relay_url: &str,
    client_pubkey_hex: &str,
    remote_pubkey_hex: &str,
    client_keys: &Keys,
) -> Result<PublicKey, NostrAuthError> {
    let req_id = generate_request_id();
    let req = serde_json::json!({"id": req_id, "method": "get_public_key", "params": []});
    let req_json =
        serde_json::to_string(&req).map_err(|e| NostrAuthError::Serialization(e.to_string()))?;

    let remote_pk = PublicKey::from_hex(remote_pubkey_hex)
        .map_err(|e| NostrAuthError::InvalidPublicKey(e.to_string()))?;

    let encrypted = nostr::nips::nip44::encrypt(
        client_keys.secret_key(),
        &remote_pk,
        &req_json,
        nostr::nips::nip44::Version::V2,
    )
    .map_err(|e| NostrAuthError::BunkerConnectionFailed(e.to_string()))?;

    let event = nostr::EventBuilder::new(nostr::Kind::Custom(24133), encrypted)
        .tag(nostr::Tag::public_key(remote_pk))
        .sign_with_keys(client_keys)
        .map_err(|e| NostrAuthError::BunkerConnectionFailed(e.to_string()))?;

    let result = websocket_rpc_call(
        relay_url,
        &event.as_json(),
        client_pubkey_hex,
        remote_pubkey_hex,
        client_keys,
        &req_id,
        15,
    )
    .await?;

    let v: serde_json::Value = serde_json::from_str(&result)
        .map_err(|e| NostrAuthError::BunkerConnectionFailed(e.to_string()))?;
    let hex = v
        .as_str()
        .or_else(|| v["result"].as_str())
        .ok_or_else(|| NostrAuthError::BunkerConnectionFailed("no pubkey in response".into()))?;

    PublicKey::from_hex(hex).map_err(|e| NostrAuthError::InvalidPublicKey(e.to_string()))
}

/// Opens a WebSocket connection to a relay, sends a REQ subscription for the response,
/// sends the event, waits for a NIP-46 response event addressed to our ephemeral key,
/// decrypts it, and returns the plaintext result.
async fn websocket_rpc_call(
    relay_url: &str,
    event_json: &str,
    client_pubkey_hex: &str,
    remote_pubkey_hex: &str,
    client_keys: &Keys,
    req_id: &str,
    timeout_secs: u32,
) -> Result<String, NostrAuthError> {
    use wasm_bindgen::closure::Closure;

    // Using a Promise-based approach for the WebSocket async lifecycle.
    // We create a promise that resolves when we get the response event.
    let resolve_cell: std::rc::Rc<RefCell<Option<js_sys::Function>>> =
        std::rc::Rc::new(RefCell::new(None));
    let reject_cell: std::rc::Rc<RefCell<Option<js_sys::Function>>> =
        std::rc::Rc::new(RefCell::new(None));

    let resolve_cell_clone = resolve_cell.clone();
    let reject_cell_clone = reject_cell.clone();

    let client_keys_clone = client_keys.clone();
    let client_pubkey_hex_owned = client_pubkey_hex.to_string();
    let remote_pubkey_hex_owned = remote_pubkey_hex.to_string();
    let req_id_owned = req_id.to_string();
    let event_json_owned = event_json.to_string();
    let relay_url_owned = relay_url.to_string();

    let promise = Promise::new(&mut |resolve, reject| {
        *resolve_cell_clone.borrow_mut() = Some(resolve);
        *reject_cell_clone.borrow_mut() = Some(reject);
    });

    let resolve_fn = resolve_cell.borrow().clone();
    let reject_fn = reject_cell.borrow().clone();

    // WebSocket setup
    let ws = web_sys::WebSocket::new(&relay_url_owned)
        .map_err(|e| NostrAuthError::BunkerConnectionFailed(format!("WebSocket: {e:?}")))?;

    ws.set_binary_type(web_sys::BinaryType::Arraybuffer);

    let ws_clone = ws.clone();
    let event_json_clone = event_json_owned.clone();
    let client_pubkey_hex_clone = client_pubkey_hex_owned.clone();
    let req_id_clone = req_id_owned.clone();

    // On open: subscribe and send the event
    let on_open = Closure::<dyn FnMut(_)>::new(move |_: web_sys::Event| {
        // Subscribe to events addressed to our client pubkey (NIP-46 responses)
        let sub_id = format!("nip46-{}", &req_id_clone[..8]);
        let req_msg = serde_json::json!([
            "REQ",
            sub_id,
            {
                "kinds": [24133],
                "#p": [client_pubkey_hex_clone]
            }
        ]);
        let _ = ws_clone.send_with_str(&req_msg.to_string());
        // Send our NIP-46 request event
        let event_msg = serde_json::json!([
            "EVENT",
            serde_json::from_str::<serde_json::Value>(&event_json_clone).unwrap_or_default()
        ]);
        let _ = ws_clone.send_with_str(&event_msg.to_string());
    });

    // On message: look for EVENT matching our request ID
    let keys_for_closure = client_keys_clone.clone();
    let remote_hex_for_closure = remote_pubkey_hex_owned.clone();
    let req_id_for_closure = req_id_owned.clone();
    let resolve_for_msg = resolve_fn.clone();
    let reject_for_msg = reject_fn.clone();

    let on_message = Closure::<dyn FnMut(_)>::new(move |e: web_sys::MessageEvent| {
        let Some(data) = e.data().as_string() else {
            return;
        };
        let msg: serde_json::Value = match serde_json::from_str(&data) {
            Ok(v) => v,
            Err(_) => return,
        };
        if msg[0].as_str() != Some("EVENT") {
            return;
        }
        let event_obj = &msg[2];
        // Must be kind 24133 from the remote signer addressed to us
        if event_obj["kind"].as_u64() != Some(24133) {
            return;
        }
        let from_hex = event_obj["pubkey"].as_str().unwrap_or_default();
        if from_hex != remote_hex_for_closure {
            return;
        }
        let ciphertext = match event_obj["content"].as_str() {
            Some(s) => s.to_string(),
            None => return,
        };
        // Decrypt with NIP-44 using our ephemeral secret key
        let Ok(remote_pk) = PublicKey::from_hex(&remote_hex_for_closure) else {
            return;
        };
        let Ok(plaintext) =
            nostr::nips::nip44::decrypt(keys_for_closure.secret_key(), &remote_pk, &ciphertext)
        else {
            return;
        };
        // Parse NIP-46 response and check the id matches
        let resp: serde_json::Value = match serde_json::from_str(&plaintext) {
            Ok(v) => v,
            Err(_) => return,
        };
        if resp["id"].as_str() != Some(&req_id_for_closure) {
            return;
        }
        if let Some(err) = resp["error"].as_str().filter(|s| !s.is_empty()) {
            let _ = reject_for_msg
                .as_ref()
                .map(|f| f.call1(&JsValue::UNDEFINED, &JsValue::from_str(err)));
            return;
        }
        let result = resp["result"].to_string();
        let _ = resolve_for_msg
            .as_ref()
            .map(|f| f.call1(&JsValue::UNDEFINED, &JsValue::from_str(&result)));
    });

    let reject_for_err = reject_fn.clone();
    let on_error = Closure::<dyn FnMut(_)>::new(move |_: web_sys::ErrorEvent| {
        let _ = reject_for_err
            .as_ref()
            .map(|f| f.call1(&JsValue::UNDEFINED, &JsValue::from_str("WebSocket error")));
    });

    ws.set_onopen(Some(on_open.as_ref().unchecked_ref()));
    ws.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
    ws.set_onerror(Some(on_error.as_ref().unchecked_ref()));

    on_open.forget();
    on_message.forget();
    on_error.forget();

    // Race the promise against a timeout
    let timeout_ms = (timeout_secs as f64) * 1000.0;
    let timeout_promise = Promise::new(&mut |_resolve, reject| {
        let cb = Closure::once(move || {
            let _ = reject.call1(&JsValue::UNDEFINED, &JsValue::from_str("timeout"));
        });
        web_sys::window()
            .unwrap()
            .set_timeout_with_callback_and_timeout_and_arguments_0(
                cb.as_ref().unchecked_ref(),
                timeout_ms as i32,
            )
            .unwrap();
        cb.forget();
    });

    let race = js_sys::Promise::race(&Array::of2(&promise, &timeout_promise));

    let result = JsFuture::from(race).await.map_err(|e| {
        let msg = e.as_string().unwrap_or_else(|| "connection failed".into());
        if msg == "timeout" {
            NostrAuthError::BunkerTimeout
        } else {
            NostrAuthError::BunkerConnectionFailed(msg)
        }
    })?;

    // Close WebSocket after we have our result
    let _ = ws.close();

    result
        .as_string()
        .ok_or_else(|| NostrAuthError::BunkerConnectionFailed("invalid response".into()))
}

fn generate_request_id() -> String {
    // Use Math.random() for a simple unique ID in WASM context
    let rand: f64 = js_sys::Math::random();
    format!("{:016x}", (rand * f64::from(u32::MAX)) as u64)
}

// ─────────────────────────────────────────────
//  Passkey — WebAuthn PRF (Roadflare pattern)
// ─────────────────────────────────────────────

/// Fixed PRF salt (same as Roadflare iOS: `SHA256("nostr-key-v1")` raw bytes passed as salt).
/// This constant is the UTF-8 bytes of "nostr-key-v1" — WebAuthn PRF hashes them internally.
const PRF_SALT: &[u8] = b"nostr-key-v1";

/// An active passkey session. The secret key is in-memory only; derived anew on each login.
/// The passkey (and by extension, your Nostr identity) syncs via iCloud Keychain on Apple
/// devices, or Google Password Manager / Windows Hello on other platforms.
#[derive(Clone)]
pub struct PasskeySession {
    pub public_key: PublicKey,
    secret_key: SecretKey,
    /// base64url-encoded credential ID — stored in PersistedSession for restore
    pub credential_id: Vec<u8>,
}

impl PasskeySession {
    /// Create a brand-new Nostr identity backed by a passkey.
    ///
    /// On macOS/iOS: triggers Touch ID / Face ID sheet. The resulting passkey
    /// syncs via iCloud Keychain to all the user's Apple devices.
    pub async fn create(rp_id: &str, rp_name: &str) -> Result<Self, NostrAuthError> {
        let window = web_sys::window()
            .ok_or_else(|| NostrAuthError::PasskeyFailed("no window object".into()))?;
        let credentials = window.navigator().credentials();

        // Build a random user ID (not linked to the Nostr key — just for WebAuthn bookkeeping)
        let user_id = random_bytes(16);
        let user_id_u8 = Uint8Array::from(user_id.as_slice());

        // Build the creation options object using js-sys Reflect
        let options = Object::new();
        let pk_opts = Object::new();

        // rp
        let rp = Object::new();
        set_str(&rp, "id", rp_id);
        set_str(&rp, "name", rp_name);
        set(&pk_opts, "rp", &rp);

        // user
        let user = Object::new();
        Reflect::set(&user, &"id".into(), &user_id_u8).unwrap();
        set_str(&user, "name", "nostr");
        set_str(&user, "displayName", "Nostr Identity");
        set(&pk_opts, "user", &user);

        // challenge
        let challenge = Uint8Array::from(random_bytes(32).as_slice());
        set(&pk_opts, "challenge", &challenge);

        // pubKeyCredParams: ES256 (-7)
        let param = Object::new();
        set_str(&param, "type", "public-key");
        Reflect::set(&param, &"alg".into(), &(-7_i32).into()).unwrap();
        let params = Array::of1(&param);
        set(&pk_opts, "pubKeyCredParams", &params);

        // authenticatorSelection: prefer platform, resident key required
        let auth_sel = Object::new();
        set_str(&auth_sel, "authenticatorAttachment", "platform");
        set_str(&auth_sel, "residentKey", "required");
        set_str(&auth_sel, "userVerification", "required");
        set(&pk_opts, "authenticatorSelection", &auth_sel);

        // extensions: prf with our fixed salt
        let extensions = Object::new();
        let prf = Object::new();
        let prf_eval = Object::new();
        let salt_u8 = Uint8Array::from(PRF_SALT);
        // first: SHA-256 of "nostr-key-v1" would be more correct per Roadflare,
        // but WebAuthn PRF uses HMAC-SHA-256 internally so raw bytes are fine as-is.
        Reflect::set(&prf_eval, &"first".into(), &salt_u8).unwrap();
        set(&prf, "eval", &prf_eval);
        set(&extensions, "prf", &prf);
        set(&pk_opts, "extensions", &extensions);

        set(&options, "publicKey", &pk_opts);

        let promise = credentials
            .create_with_options(&options.unchecked_into())
            .map_err(|e| NostrAuthError::PasskeyFailed(format!("{e:?}")))?;

        let credential = JsFuture::from(promise).await.map_err(|e| {
            web_sys::console::error_1(&e);
            NostrAuthError::PasskeyFailed(js_err_msg(e))
        })?;

        Self::derive_from_credential(credential)
    }

    /// Authenticate with an existing passkey using its credential ID.
    ///
    /// On macOS/iOS: triggers Touch ID / Face ID sheet.
    /// The same passkey + same PRF salt always produces the same Nostr key (deterministic).
    pub async fn authenticate(credential_id: Vec<u8>) -> Result<Self, NostrAuthError> {
        let window = web_sys::window()
            .ok_or_else(|| NostrAuthError::PasskeyFailed("no window object".into()))?;
        let credentials = window.navigator().credentials();

        let options = Object::new();
        let pk_opts = Object::new();

        let challenge = Uint8Array::from(random_bytes(32).as_slice());
        set(&pk_opts, "challenge", &challenge);
        set_str(&pk_opts, "userVerification", "required");

        // Allow only the stored credential
        let cred_descriptor = Object::new();
        set_str(&cred_descriptor, "type", "public-key");
        let cred_id_u8 = Uint8Array::from(credential_id.as_slice());
        set(&cred_descriptor, "id", &cred_id_u8);
        let allow_creds = Array::of1(&cred_descriptor);
        set(&pk_opts, "allowCredentials", &allow_creds);

        // PRF extension — evalByCredential keyed by base64url credential ID
        let cred_id_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&credential_id);
        let extensions = Object::new();
        let prf = Object::new();
        let eval_by_cred = Object::new();
        let prf_eval = Object::new();
        let salt_u8 = Uint8Array::from(PRF_SALT);
        Reflect::set(&prf_eval, &"first".into(), &salt_u8).unwrap();
        Reflect::set(&eval_by_cred, &cred_id_b64.into(), &prf_eval).unwrap();
        set(&prf, "evalByCredential", &eval_by_cred);
        set(&extensions, "prf", &prf);
        set(&pk_opts, "extensions", &extensions);

        set(&options, "publicKey", &pk_opts);

        let promise = credentials
            .get_with_options(&options.unchecked_into())
            .map_err(|e| NostrAuthError::PasskeyFailed(format!("{e:?}")))?;

        let credential = JsFuture::from(promise).await.map_err(|e| {
            web_sys::console::error_1(&e);
            NostrAuthError::PasskeyFailed(js_err_msg(e))
        })?;

        Self::derive_from_credential(credential)
    }

    /// Derive the Nostr keypair from a WebAuthn credential's PRF output.
    ///
    /// Flow (mirrors Roadflare iOS):
    ///   PRF output (32 bytes) → SHA-256 → secp256k1 private key
    fn derive_from_credential(credential: JsValue) -> Result<Self, NostrAuthError> {
        // Extract credential ID
        let raw_id = Reflect::get(&credential, &"rawId".into())
            .map_err(|_| NostrAuthError::PasskeyFailed("no rawId".into()))?;
        let cred_id_u8 = Uint8Array::new(&raw_id);
        let credential_id = cred_id_u8.to_vec();

        // Navigate: credential.getClientExtensionResults().prf.results.first
        let get_exts = Reflect::get(&credential, &"getClientExtensionResults".into())
            .and_then(|f| {
                f.dyn_ref::<js_sys::Function>()
                    .ok_or(JsValue::UNDEFINED)?
                    .call0(&credential)
            })
            .map_err(|_| {
                NostrAuthError::PasskeyFailed("getClientExtensionResults failed".into())
            })?;

        let prf_results = Reflect::get(&get_exts, &"prf".into())
            .and_then(|p| Reflect::get(&p, &"results".into()))
            .map_err(|_| NostrAuthError::PasskeyNotSupported)?;

        if prf_results.is_undefined() || prf_results.is_null() {
            return Err(NostrAuthError::PasskeyNotSupported);
        }

        let first = Reflect::get(&prf_results, &"first".into())
            .map_err(|_| NostrAuthError::PasskeyFailed("no PRF first output".into()))?;

        let prf_bytes = Uint8Array::new(&first).to_vec();

        if prf_bytes.len() < 32 {
            return Err(NostrAuthError::PasskeyFailed("PRF output too short".into()));
        }

        // SHA-256 of the PRF output → secp256k1 private key (deterministic, Roadflare pattern)
        // We compute SHA-256 synchronously using the nostr/bitcoin_hashes dependency.
        let digest = sha256_bytes(&prf_bytes);

        let secret_key = SecretKey::from_slice(&digest)
            .map_err(|e| NostrAuthError::PasskeyFailed(e.to_string()))?;

        let keys = Keys::new(secret_key.clone());
        let public_key = keys.public_key();

        Ok(Self {
            public_key,
            secret_key,
            credential_id,
        })
    }

    /// Sign a Nostr event using the in-memory derived key.
    pub fn sign_event(&self, event_json: &str) -> Result<String, NostrAuthError> {
        let unsigned: nostr::UnsignedEvent = serde_json::from_str(event_json)
            .map_err(|e| NostrAuthError::Serialization(e.to_string()))?;
        let keys = Keys::new(self.secret_key.clone());
        let signed = unsigned
            .sign_with_keys(&keys)
            .map_err(|e| NostrAuthError::SigningFailed(e.to_string()))?;
        serde_json::to_string(&signed).map_err(|e| NostrAuthError::Serialization(e.to_string()))
    }
}

/// Compute SHA-256 synchronously (using the `nostr` crate's transitive dep).
fn sha256_bytes(input: &[u8]) -> [u8; 32] {
    use nostr::hashes::{sha256, Hash};
    let mut engine = sha256::Hash::engine();
    nostr::hashes::HashEngine::input(&mut engine, input);
    let hash = sha256::Hash::from_engine(engine);
    hash.to_byte_array()
}

fn random_bytes(len: usize) -> Vec<u8> {
    let window = web_sys::window().unwrap();
    let crypto = window.crypto().unwrap();
    let mut buf = vec![0u8; len];
    let u8arr = Uint8Array::new_with_length(len as u32);
    crypto
        .get_random_values_with_array_buffer_view(&u8arr)
        .unwrap();
    u8arr.copy_to(&mut buf);
    buf
}

/// Extract a human-readable message from any JS error value.
/// DOMException / Error objects expose a `.message` string property;
/// plain string rejections are returned as-is.
fn js_err_msg(e: JsValue) -> String {
    e.as_string()
        .or_else(|| {
            Reflect::get(&e, &"message".into())
                .ok()
                .and_then(|v| v.as_string())
        })
        .unwrap_or_else(|| format!("{e:?}"))
}

fn set(obj: &Object, key: &str, val: &JsValue) {
    Reflect::set(obj, &key.into(), val).unwrap();
}
fn set_str(obj: &Object, key: &str, val: &str) {
    Reflect::set(obj, &key.into(), &JsValue::from_str(val)).unwrap();
}

// ─────────────────────────────────────────────
//  Read-Only
// ─────────────────────────────────────────────

/// Read-only access — public key only, no signing capability.
#[derive(Clone)]
pub struct ReadOnlyHandle {
    pub public_key: PublicKey,
}

impl std::str::FromStr for ReadOnlyHandle {
    type Err = NostrAuthError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let input = input.trim();
        if let Ok(pk) = PublicKey::from_hex(input) {
            return Ok(Self { public_key: pk });
        }
        if let Ok(pk) = PublicKey::from_bech32(input) {
            return Ok(Self { public_key: pk });
        }
        if input.starts_with("nprofile") {
            if let Ok(profile) = nostr::nips::nip19::Nip19Profile::from_bech32(input) {
                return Ok(Self { public_key: profile.public_key });
            }
        }
        Err(NostrAuthError::InvalidPublicKey(
            "Expected npub1..., nprofile1..., or 64-char hex public key".into(),
        ))
    }
}

// ─────────────────────────────────────────────
//  RawKeySession — ncryptsec (NIP-49) + raw nsec
// ─────────────────────────────────────────────

/// In-memory raw key session. Used for NIP-49 ncryptsec and (feature-gated) raw nsec paste.
/// The secret key is zeroed when this struct is dropped.
#[derive(Clone)]
pub struct RawKeySession {
    pub public_key: PublicKey,
    secret_key: SecretKey,
}

impl RawKeySession {
    /// Decrypt a NIP-49 `ncryptsec1...` string with a password.
    ///
    /// scrypt derivation is CPU-intensive — call this inside `spawn_local` to avoid
    /// blocking the browser's main thread while the spinner shows.
    pub fn from_ncryptsec(ncryptsec: &str, password: &str) -> Result<Self, NostrAuthError> {
        let encrypted = nostr::nips::nip49::EncryptedSecretKey::from_bech32(ncryptsec)
            .map_err(|e| NostrAuthError::InvalidNcryptsec(e.to_string()))?;

        let secret_key = encrypted
            .decrypt(password)
            .map_err(|_| NostrAuthError::WrongPassword)?;

        let keys = Keys::new(secret_key.clone());
        Ok(Self {
            public_key: keys.public_key(),
            secret_key,
        })
    }

    /// Parse a raw `nsec1...` bech32 or 64-char hex private key.
    ///
    /// Only available with the `insecure_nsec_input` feature flag.
    #[cfg(feature = "insecure_nsec_input")]
    pub fn from_nsec_or_hex(input: &str) -> Result<Self, NostrAuthError> {
        let input = input.trim();
        let secret_key = if let Ok(sk) = SecretKey::from_bech32(input) {
            sk
        } else if let Ok(sk) = SecretKey::from_hex(input) {
            sk
        } else {
            return Err(NostrAuthError::InvalidSecretKey(
                "Expected nsec1... (bech32) or 64-char hex private key".into(),
            ));
        };
        let keys = Keys::new(secret_key.clone());
        Ok(Self {
            public_key: keys.public_key(),
            secret_key,
        })
    }

    /// Sign a Nostr event with the in-memory key.
    pub fn sign_event(&self, event_json: &str) -> Result<String, NostrAuthError> {
        let unsigned: nostr::UnsignedEvent = serde_json::from_str(event_json)
            .map_err(|e| NostrAuthError::Serialization(e.to_string()))?;
        let keys = Keys::new(self.secret_key.clone());
        let signed = unsigned
            .sign_with_keys(&keys)
            .map_err(|e| NostrAuthError::SigningFailed(e.to_string()))?;
        serde_json::to_string(&signed).map_err(|e| NostrAuthError::Serialization(e.to_string()))
    }
}
