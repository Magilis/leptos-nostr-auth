use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;

use crate::modal::NostrAuthModal;
use crate::signers::AuthResult;
use crate::storage;
use crate::types::NostrAuthConfig;

/// Reactive auth context — available anywhere inside [`NostrAuthProvider`].
///
/// Access via [`use_nostr_auth()`].
#[derive(Clone, Copy)]
pub struct NostrAuthContext {
    /// Current auth result; `None` when not logged in.
    pub auth: Signal<Option<AuthResult>>,
    /// Convenience: the authenticated user's public key (bech32 npub and hex).
    pub public_key: Signal<Option<nostr::PublicKey>>,
    /// `true` when a user is logged in.
    pub is_authenticated: Signal<bool>,
    /// Open the login modal programmatically.
    pub show_login: Callback<()>,
    /// Log out: clears auth state and removes the localStorage session.
    pub logout: Callback<()>,
}

/// Retrieve the Nostr auth context.
///
/// **Panics** if called outside a [`NostrAuthProvider`] tree.
pub fn use_nostr_auth() -> NostrAuthContext {
    use_context::<NostrAuthContext>()
        .expect("`use_nostr_auth` must be called inside a `<NostrAuthProvider>` component")
}

/// Wraps your application root to provide reactive Nostr authentication state.
///
/// Automatically attempts to restore a cached session from localStorage on mount.
/// Renders [`NostrAuthModal`] internally so you don't need to add it yourself.
///
/// # Example
/// ```rust,ignore
/// fn App() -> impl IntoView {
///     view! {
///         <NostrAuthProvider>
///             <HomePage />
///         </NostrAuthProvider>
///     }
/// }
/// ```
#[component]
pub fn NostrAuthProvider(
    /// Optional configuration (default: all methods enabled, persistence on).
    #[prop(optional)]
    config: Option<NostrAuthConfig>,
    children: Children,
) -> impl IntoView {
    let config = config.unwrap_or_default();
    let cfg = StoredValue::new(config.clone());

    let (auth, set_auth) = signal(None::<AuthResult>);
    let (show_modal, set_show_modal) = signal(false);
    let (restoring, set_restoring) = signal(false);

    // On mount: attempt session restore from localStorage
    Effect::new(move |_| {
        if cfg.get_value().persist_session {
            if let Some(session) = storage::load_session(cfg.get_value().storage_key) {
                set_restoring.set(true);
                spawn_local(async move {
                    match storage::restore_session(&session).await {
                        Ok(result) => {
                            set_auth.set(Some(result));
                        }
                        Err(e) => {
                            // Session no longer valid (extension changed, passkey gone, etc.)
                            web_sys::console::info_1(
                                &format!("leptos-nostr-auth: session restore failed: {e}").into(),
                            );
                            storage::clear_session(cfg.get_value().storage_key);
                        }
                    }
                    set_restoring.set(false);
                });
            }
        }
    });

    let public_key = Signal::derive(move || auth.get().map(|a| a.public_key()));
    let is_authenticated = Signal::derive(move || auth.get().is_some());

    let show_login = Callback::new(move |(): ()| set_show_modal.set(true));

    let logout = Callback::new(move |(): ()| {
        storage::clear_session(cfg.get_value().storage_key);
        set_auth.set(None);
    });

    let ctx = NostrAuthContext {
        auth: auth.into(),
        public_key,
        is_authenticated,
        show_login,
        logout,
    };

    provide_context(ctx);

    let on_auth_callback = Callback::new(move |result: AuthResult| {
        // Persist session to localStorage (if configured)
        if cfg.get_value().persist_session {
            if let Some(session) = result.to_persisted_session() {
                storage::save_session(cfg.get_value().storage_key, &session);
            }
        }
        set_auth.set(Some(result));
        set_show_modal.set(false);
    });

    let on_close_callback = Callback::new(move |(): ()| {
        set_show_modal.set(false);
    });

    view! {
        // Show a subtle loading indicator while restoring (optional — UX polish)
        <Show when=move || restoring.get() fallback=|| ()>
            <div
                aria-live="polite"
                aria-label="Restoring session…"
                data-nostr-restoring=""
                style="position:fixed;bottom:1rem;right:1rem;z-index:9997;"
                class=if cfg!(feature = "daisyui") { "badge badge-ghost gap-2 p-3" } else { "" }
            >
                <span class=if cfg!(feature = "daisyui") { "loading loading-spinner loading-xs" } else { "" } />
                "Restoring session…"
            </div>
        </Show>

        {children()}

        <NostrAuthModal
            open=Signal::from(show_modal)
            on_auth=on_auth_callback
            on_close=on_close_callback
            config=cfg.get_value()
        />
    }
}
