#[cfg(not(feature = "ssr"))]
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
    ///
    /// In SSR mode returns `server_default()` immediately (no browser APIs available).
    /// Call inside `Effect::new()` and write to a reactive signal so the UI narrows
    /// down from the full server-rendered list after hydration.
    pub fn detect() -> Self {
        #[cfg(feature = "ssr")]
        {
            return Self::server_default();
        }

        #[cfg(not(feature = "ssr"))]
        {
            let Some(window) = web_sys::window() else {
                return Self::server_default();
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
    }

    /// Used on the server and as the pre-hydration initial state on the client.
    ///
    /// All visibility flags are `true` so the server renders the complete method list.
    /// `is_android` and `is_apple` are `false` for neutral ordering (no Apple-first
    /// layout, no Amber tip). After hydration, `Effect::new()` calls `detect()` and
    /// updates the platform signal, reactively narrowing the list to real capabilities.
    pub(crate) fn server_default() -> Self {
        Self {
            has_nostr_extension: true,
            is_android: false,
            is_apple: false,
            supports_webauthn: true,
        }
    }
}
