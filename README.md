# leptos-nostr-auth

Headless Nostr authentication modal widget for [Leptos](https://leptos.dev) applications.

Drop-in login modal supporting every Nostr authentication method. Headless by default — bring your own CSS. Optional daisyUI dark-theme styling via a feature flag.

## Login Methods

| Method | When shown |
|---|---|
| Browser Extension (NIP-07) | Alby, nos2x, Nostr KeyX detected |
| Nostr Connect / Bunker (NIP-46) | Always |
| Passkey (WebAuthn PRF) | macOS/iOS: **top position** (Face ID/Touch ID); others: if WebAuthn available |
| Read-Only (npub) | Always |
| Encrypted Key / ncryptsec (NIP-49) | Always |
| Amber deep-link | Android user-agent only |
| Raw nsec paste | Only with `insecure_nsec_input` feature (opt-in) |

Passkeys use the WebAuthn PRF extension with a fixed salt (`"nostr-key-v1"`) to deterministically derive the same secp256k1 key from the same passkey on any device. On Apple devices, passkeys sync silently via iCloud Keychain — no passwords, no clipboard.

## Quick Start

```toml
# Cargo.toml
[dependencies]
leptos-nostr-auth = "0.1"
```

```rust
use leptos::prelude::*;
use leptos_nostr_auth::{use_nostr_auth, NostrAuthProvider};

fn main() {
    leptos::mount::mount_to_body(App);
}

#[component]
fn App() -> impl IntoView {
    view! {
        <NostrAuthProvider>
            <HomePage />
        </NostrAuthProvider>
    }
}

#[component]
fn HomePage() -> impl IntoView {
    let auth = use_nostr_auth();
    view! {
        <Show
            when=move || auth.is_authenticated.get()
            fallback=move || view! {
                <button on:click=move |_| auth.show_login.run(())>
                    "Login with Nostr"
                </button>
            }
        >
            <p>"Logged in as: " {move || auth.public_key.get()
                .and_then(|pk| pk.to_bech32().ok())
                .unwrap_or_default()}
            </p>
            <button on:click=move |_| auth.logout.run(())>"Logout"</button>
        </Show>
    }
}
```

## Feature Flags

### `daisyui` — pre-styled dark theme

```toml
leptos-nostr-auth = { version = "0.1", features = ["daisyui"] }
```

Enables daisyUI 5 + Tailwind v4 styling with a dark theme scoped to the modal.

**Additional setup required:**

1. Install Tailwind CSS v4 and daisyUI v5 in your build pipeline (via Trunk or cargo-leptos).

2. In your `style/tailwind.css` (or equivalent):
   ```css
   @import "tailwindcss";
   @plugin "daisyui";
   ```

3. Add the library's WASM output to Tailwind's content paths so class names aren't purged:
   ```js
   // tailwind.config.js (if using config file)
   export default {
     content: [
       "./src/**/*.rs",
       "./pkg/**/*.js",   // compiled WASM JS glue
     ],
   };
   ```

### `insecure_nsec_input` — raw secret key paste (opt-in only)

```toml
leptos-nostr-auth = { version = "0.1", features = ["insecure_nsec_input"] }
```

Shows a raw `nsec1...` / hex private key input behind a two-click security warning. **Not recommended** for production — any XSS on the page can steal the key. Use a browser extension, passkey, or ncryptsec instead.

## Configuration

```rust
use leptos_nostr_auth::NostrAuthConfig;

let config = NostrAuthConfig {
    // Persist session to localStorage (default: true)
    persist_session: true,

    // localStorage key (default: "leptos_nostr_auth_session")
    storage_key: "my_app_nostr_session",

    // Close modal on backdrop click (default: true)
    close_on_backdrop_click: true,

    // Close modal on Escape key (default: true)
    close_on_escape: true,

    // REQUIRED for passkey: your domain (no https:// prefix)
    // Default: window.location.hostname
    rp_id: Some("myapp.com".into()),

    // WebAuthn relying party display name (default: "Nostr App")
    rp_name: "My App",

    // NIP-46 connection timeout in seconds (default: 30)
    bunker_timeout_secs: 30,

    ..Default::default()
};

view! {
    <NostrAuthProvider config=config>
        <App />
    </NostrAuthProvider>
}
```

## Passkey Setup (macOS / iOS)

Passkeys are scoped to a **Relying Party ID** (your domain). You **must** configure `rp_id`:

```rust
NostrAuthConfig {
    rp_id: Some("myapp.com".into()), // must match window.location.hostname exactly
    ..Default::default()
}
```

Passkeys created on `myapp.com` only work on `myapp.com`. On localhost for development, use `rp_id: Some("localhost".into())`.

**How it works (Roadflare iOS pattern ported to WebAuthn):**

1. Browser calls `navigator.credentials.create()` with PRF extension and salt `"nostr-key-v1"`
2. OS shows Touch ID / Face ID sheet (macOS/iOS) or platform authenticator
3. PRF returns a deterministic 32-byte output
4. SHA-256 of that output becomes the secp256k1 private key
5. Only the passkey credential ID is stored in localStorage — no private key bytes

Same passkey on any device → same Nostr identity. Syncs automatically via iCloud Keychain on Apple, Google Password Manager on Android, Windows Hello on Windows.

## Raw Modal (without context provider)

```rust
let (show, set_show) = signal(false);

view! {
    <button on:click=move |_| set_show(true)>"Login"</button>
    <NostrAuthModal
        open=show.into()
        on_auth=move |result| {
            // result: AuthResult::Extension | Bunker | Passkey | ReadOnly | Ncryptsec
            let pubkey = result.public_key();
        }
        on_close=move |_| set_show(false)
    />
}
```

## Working with AuthResult

```rust
use leptos_nostr_auth::AuthResult;

let auth = use_nostr_auth();

// Public key (always available)
let pubkey: Signal<Option<nostr::PublicKey>> = auth.public_key;

// Sign an event (match on variant for signing capability)
// Note: ReadOnly and Ncryptsec variants have different async characteristics.
// Extension and Bunker variants can sign asynchronously via their handles.
// Passkey and RawKey variants sign synchronously in-memory.
```

## Session Restore

When `persist_session: true` (default), successful logins are cached in localStorage:

| Method | Restore behavior |
|---|---|
| Extension | Re-calls `window.nostr.getPublicKey()`, verifies pubkey matches |
| Bunker | Re-establishes WebSocket connection using stored `bunker://` URI |
| Passkey | Calls `navigator.credentials.get()` → biometric → re-derives same key |
| Read-Only | Restores directly from stored hex pubkey |
| ncryptsec | **Not persisted** — user must decrypt again (password not stored) |

To disable persistence:

```rust
NostrAuthConfig { persist_session: false, ..Default::default() }
```

## Headless CSS Hooks

Without the `daisyui` feature, all elements emit `data-nostr-*` attributes for styling:

```css
[data-nostr-backdrop] { /* modal overlay */ }
[data-nostr-modal] { /* modal box */ }
[data-nostr-modal-title] { /* "Connect to Nostr" heading */ }
[data-nostr-method] { /* login method button */ }
[data-nostr-method-icon] { /* method icon wrapper */ }
[data-nostr-method-title] { /* method name */ }
[data-nostr-method-subtitle] { /* method description */ }
[data-nostr-badge] { /* "Recommended" badge */ }
[data-nostr-error] { /* error message */ }
[data-nostr-warning] { /* security warning */ }
[data-nostr-input] { /* text inputs */ }
[data-nostr-back] { /* back button */ }
[data-nostr-close] { /* close button */ }
```

## License

MIT
