use wasm_bindgen::JsValue;

/// Runtime platform capabilities detected once at startup.
#[derive(Clone, Copy, Debug)]
pub struct Platform {
    /// `window.nostr` is present (NIP-07 browser extension installed)
    pub has_nostr_extension: bool,
    /// Android user-agent detected — show Amber NIP-46 hint
    pub is_android: bool,
    /// macOS or iOS user-agent — show passkey as the primary recommended option
    pub is_apple: bool,
    /// `navigator.credentials` exists (WebAuthn is available; PRF confirmed at runtime)
    pub supports_webauthn: bool,
}

impl Platform {
    /// Detect platform capabilities from browser APIs.
    /// Call once and store in a `leptos::StoredValue`.
    pub fn detect() -> Self {
        let Some(window) = web_sys::window() else {
            return Self::unknown();
        };

        let has_nostr_extension =
            js_sys::Reflect::has(&JsValue::from(window.clone()), &JsValue::from_str("nostr"))
                .unwrap_or(false);

        let navigator = window.navigator();

        let user_agent = navigator.user_agent().unwrap_or_default().to_lowercase();

        let is_android = user_agent.contains("android");

        // Detect macOS and iOS/iPadOS.
        // Note: iPadOS 13+ reports as Macintosh in desktop mode, so we check both.
        let is_apple = (user_agent.contains("macintosh")
            || user_agent.contains("iphone")
            || user_agent.contains("ipad"))
            && !is_android;

        // WebAuthn availability: navigator.credentials must exist.
        // Actual PRF support is confirmed when credentials.create() returns PRF results.
        let supports_webauthn = {
            let creds =
                js_sys::Reflect::get(&JsValue::from(navigator), &JsValue::from_str("credentials"))
                    .ok();
            matches!(creds, Some(ref v) if !v.is_undefined() && !v.is_null())
        };

        Self {
            has_nostr_extension,
            is_android,
            is_apple,
            supports_webauthn,
        }
    }

    fn unknown() -> Self {
        Self {
            has_nostr_extension: false,
            is_android: false,
            is_apple: false,
            supports_webauthn: false,
        }
    }
}
