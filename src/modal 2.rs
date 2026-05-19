// Suppressed: #[component] generates exhaustive props structs we cannot control.
#![allow(clippy::exhaustive_structs, clippy::missing_docs_in_private_items)]
use leptos::portal::Portal;
use leptos::prelude::*;
use leptos_use::{use_event_listener, use_window};

#[cfg(not(feature = "ssr"))]
use wasm_bindgen_futures::spawn_local;

use crate::platform::Platform;
#[cfg(not(feature = "ssr"))]
use crate::signers::{BunkerSession, Nip07Handle, PasskeySession};
// RawKeySession: used in spawn_local (non-ssr) and in StepRawNsec sync code (insecure_nsec_input)
#[cfg(any(not(feature = "ssr"), feature = "insecure_nsec_input"))]
use crate::signers::RawKeySession;
use crate::signers::{AuthResult, ReadOnlyHandle};
use crate::types::{LoginMethod, NostrAuthConfig};

/// Which form is currently shown inside the modal.
#[derive(Clone, PartialEq)]
enum ModalStep {
    /// Login method picker list.
    MethodSelect,
    /// NIP-07 browser extension flow.
    Extension,
    /// NIP-46 bunker URI entry flow.
    Bunker,
    /// WebAuthn passkey flow.
    Passkey,
    /// Read-only public key entry flow.
    ReadOnly,
    /// NIP-49 ncryptsec password entry flow.
    Ncryptsec,
    /// Security warning shown before the raw nsec entry step.
    #[cfg(feature = "insecure_nsec_input")]
    RawNsecWarn,
    /// Raw nsec / hex key paste flow (requires `insecure_nsec_input`).
    #[cfg(feature = "insecure_nsec_input")]
    RawNsec,
}

impl ModalStep {
    /// Header title displayed while this step is active.
    const fn title(&self) -> &'static str {
        match self {
            Self::MethodSelect => "Connect to Nostr",
            Self::Extension => "Browser Extension",
            Self::Bunker => "Nostr Connect",
            Self::Passkey => "Passkey",
            Self::ReadOnly => "Read-Only Access",
            Self::Ncryptsec => "Encrypted Key",
            #[cfg(feature = "insecure_nsec_input")]
            Self::RawNsecWarn | Self::RawNsec => "Secret Key",
        }
    }
}

/// Sub-step within the passkey flow.
#[derive(Clone, PartialEq)]
enum PasskeySubStep {
    /// Choose between creating a new passkey or authenticating with an existing one.
    Choose,
    /// WebAuthn ceremony in progress.
    Loading,
}

/// The Nostr login modal widget.
///
/// Can be used standalone (you manage the `open` signal) or via [`NostrAuthProvider`].
///
/// # Example
/// ```rust,ignore
/// let (show, set_show) = signal(false);
/// view! {
///     <button on:click=move |_| set_show.set(true)>"Login"</button>
///     <NostrAuthModal
///         open=show.into()
///         on_auth=move |result| { /* handle AuthResult */ }
///     />
/// }
/// ```
#[allow(clippy::exhaustive_structs, clippy::too_many_lines)]
#[component]
pub fn NostrAuthModal(
    /// Reactive signal controlling modal visibility.
    #[prop(into)]
    open: Signal<bool>,
    /// Called with the `AuthResult` after successful login.
    on_auth: Callback<AuthResult>,
    /// Optional close callback (triggered by backdrop click / Escape key).
    #[prop(optional)]
    on_close: Option<Callback<()>>,
    /// Library configuration.
    #[prop(optional)]
    config: Option<NostrAuthConfig>,
) -> impl IntoView {
    let config = StoredValue::new(config.unwrap_or_default());

    // Starts as server_default (all methods visible, no platform bias) → Effect
    // updates to real browser capabilities after hydration so the UI narrows reactively.
    // Effects don't run on the server, so SSR always renders the full method list.
    let (platform, set_platform) = signal(Platform::server_default());
    Effect::new(move |_| {
        set_platform.set(Platform::detect());
    });

    let (step, set_step) = signal(ModalStep::MethodSelect);
    let (error, set_error) = signal(Option::<String>::None);

    let close = move || {
        set_step.set(ModalStep::MethodSelect);
        set_error.set(None);
        if let Some(cb) = on_close {
            cb.run(());
        }
    };

    // Escape key closes the modal
    let _ = use_event_listener(use_window(), leptos::ev::keydown, {
        move |e| {
            if e.key() == "Escape" && config.get_value().close_on_escape {
                close();
            }
        }
    });

    view! {
        <Portal>
            <Show when=move || open.get() fallback=|| ()>
                // Backdrop
                <div
                    data-nostr-backdrop=""
                    class=if cfg!(feature = "daisyui") { "modal modal-open" } else { "" }
                    on:click={
                        move |_| {
                            if config.get_value().close_on_backdrop_click {
                                close();
                            }
                        }
                    }
                >
                    // Modal box — stop click propagation so backdrop doesn't close when clicking inside
                    <div
                        role="dialog"
                        aria-modal="true"
                        aria-label="Connect to Nostr"
                        data-nostr-modal=""
                        data-theme=if cfg!(feature = "daisyui") { "dark" } else { "" }
                        class=if cfg!(feature = "daisyui") { "modal-box relative w-full max-w-sm" } else { "" }
                        on:click=|e| e.stop_propagation()
                    >
                        <ModalHeader
                            step=step
                            set_step=set_step
                            set_error=set_error
                            on_close=close
                        />

                        <div data-nostr-modal-body="">
                            {move || match step.get() {
                                ModalStep::MethodSelect => view! {
                                    <StepMethodSelect
                                        platform=platform
                                        config=config.get_value()
                                        set_step=set_step
                                    />
                                }.into_any(),
                                ModalStep::Extension => view! {
                                    <StepExtension
                                        on_auth=on_auth
                                        set_error=set_error
                                        set_step=set_step
                                    />
                                }.into_any(),
                                ModalStep::Bunker => view! {
                                    <StepBunker
                                        on_auth=on_auth
                                        set_error=set_error
                                        platform=platform
                                        config=config.get_value()
                                    />
                                }.into_any(),
                                ModalStep::Passkey => view! {
                                    <StepPasskey
                                        on_auth=on_auth
                                        set_error=set_error
                                        config=config.get_value()
                                    />
                                }.into_any(),
                                ModalStep::ReadOnly => view! {
                                    <StepReadOnly
                                        on_auth=on_auth
                                        set_error=set_error
                                    />
                                }.into_any(),
                                ModalStep::Ncryptsec => view! {
                                    <StepNcryptsec
                                        on_auth=on_auth
                                        set_error=set_error
                                    />
                                }.into_any(),
                                #[cfg(feature = "insecure_nsec_input")]
                                ModalStep::RawNsecWarn => view! {
                                    <StepRawNsecWarn set_step=set_step />
                                }.into_any(),
                                #[cfg(feature = "insecure_nsec_input")]
                                ModalStep::RawNsec => view! {
                                    <StepRawNsec on_auth=on_auth set_error=set_error />
                                }.into_any(),
                            }}
                        </div>

                        // Error display
                        <Show when=move || error.get().is_some() fallback=|| ()>
                            <div
                                role="alert"
                                data-nostr-error=""
                                class=if cfg!(feature = "daisyui") { "alert alert-error mt-3 text-sm py-2" } else { "" }
                            >
                                {move || error.get().unwrap_or_default()}
                            </div>
                        </Show>
                    </div>
                </div>
            </Show>
        </Portal>
    }
}

// ─── Modal Header ────────────────────────────────────────────────────────────

#[component]
fn ModalHeader(
    step: ReadSignal<ModalStep>,
    set_step: WriteSignal<ModalStep>,
    set_error: WriteSignal<Option<String>>,
    on_close: impl Fn() + 'static,
) -> impl IntoView {
    let show_back = move || step.get() != ModalStep::MethodSelect;

    view! {
        <div
            data-nostr-modal-header=""
            class=if cfg!(feature = "daisyui") { "flex items-center justify-between mb-4" } else { "" }
        >
            <div class=if cfg!(feature = "daisyui") { "flex items-center gap-2" } else { "" }>
                <Show when=show_back fallback=|| ()>
                    <button
                        aria-label="Back to login methods"
                        data-nostr-back=""
                        class=if cfg!(feature = "daisyui") { "btn btn-ghost btn-sm btn-circle" } else { "" }
                        on:click=move |_| {
                            set_step.set(ModalStep::MethodSelect);
                            set_error.set(None);
                        }
                    >
                        // ← back arrow (inline SVG)
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M19 12H5M12 5l-7 7 7 7"/>
                        </svg>
                    </button>
                </Show>
                <h2
                    data-nostr-modal-title=""
                    class=if cfg!(feature = "daisyui") { "text-lg font-semibold" } else { "" }
                >
                    {move || step.get().title()}
                </h2>
            </div>
            <button
                aria-label="Close login modal"
                data-nostr-close=""
                class=if cfg!(feature = "daisyui") { "btn btn-ghost btn-sm btn-circle" } else { "" }
                on:click=move |_| on_close()
            >
                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M18 6L6 18M6 6l12 12"/>
                </svg>
            </button>
        </div>
    }
}

// ─── Step 1: Method Selection ────────────────────────────────────────────────

#[component]
fn StepMethodSelect(
    platform: ReadSignal<Platform>,
    config: NostrAuthConfig,
    set_step: WriteSignal<ModalStep>,
) -> impl IntoView {
    let methods = config.allowed_methods;
    let has = |m: &LoginMethod| methods.contains(m);

    let passkey_allowed = has(&LoginMethod::Passkey);
    let extension_allowed = has(&LoginMethod::Extension);
    let show_bunker = has(&LoginMethod::Bunker);
    let show_readonly = has(&LoginMethod::ReadOnly);
    let show_ncryptsec = has(&LoginMethod::Ncryptsec);
    #[cfg(feature = "insecure_nsec_input")]
    let show_nsec = has(&LoginMethod::RawNsec);
    #[cfg(not(feature = "insecure_nsec_input"))]
    let show_nsec = false;

    // Reactive closures: re-evaluate when platform signal changes after hydration
    let show_passkey = move || platform.get().supports_webauthn && passkey_allowed;

    view! {
        <div data-nostr-methods="" class=if cfg!(feature = "daisyui") { "flex flex-col gap-2" } else { "" }>

            // ── Apple: passkey first ──────────────────────────────────────────
            <Show when=move || platform.get().is_apple && show_passkey() fallback=|| ()>
                <MethodButton
                    icon=icon_passkey
                    title="Passkey"
                    subtitle="Face ID / Touch ID · syncs via iCloud Keychain"
                    badge=Some("Recommended")
                    on_click=move || set_step.set(ModalStep::Passkey)
                />
            </Show>

            // ── Extension: non-Apple (badge = Recommended) ───────────────────
            // Two separate Shows so the badge value is stable per variant.
            <Show when=move || { let p = platform.get(); !p.is_apple && p.has_nostr_extension && extension_allowed } fallback=|| ()>
                <MethodButton
                    icon=icon_extension
                    title="Browser Extension"
                    subtitle="Alby, nos2x, Nostr KeyX, and more"
                    badge=Some("Recommended")
                    on_click=move || set_step.set(ModalStep::Extension)
                />
            </Show>

            // ── Extension: Apple (no badge) ───────────────────────────────────
            <Show when=move || { let p = platform.get(); p.is_apple && p.has_nostr_extension && extension_allowed } fallback=|| ()>
                <MethodButton
                    icon=icon_extension
                    title="Browser Extension"
                    subtitle="Alby, nos2x, Nostr KeyX, and more"
                    badge=None
                    on_click=move || set_step.set(ModalStep::Extension)
                />
            </Show>

            // ── Android: Amber hint before generic bunker ─────────────────────
            <Show when=move || platform.get().is_android && show_bunker fallback=|| ()>
                <MethodButton
                    icon=icon_amber
                    title="Amber"
                    subtitle="Open in Amber signer app via NIP-46"
                    badge=None
                    on_click=move || set_step.set(ModalStep::Bunker)
                />
            </Show>

            // ── Nostr Connect (Bunker) ────────────────────────────────────────
            <Show when=move || show_bunker fallback=|| ()>
                <MethodButton
                    icon=icon_bunker
                    title="Nostr Connect"
                    subtitle="Paste a bunker:// URI from nsecBunker or Amber"
                    badge=None
                    on_click=move || set_step.set(ModalStep::Bunker)
                />
            </Show>

            // ── Non-Apple: passkey after bunker ───────────────────────────────
            <Show when=move || !platform.get().is_apple && show_passkey() fallback=|| ()>
                <MethodButton
                    icon=icon_passkey
                    title="Passkey"
                    subtitle="Windows Hello · Android biometric"
                    badge=None
                    on_click=move || set_step.set(ModalStep::Passkey)
                />
            </Show>

            // ── Divider ───────────────────────────────────────────────────────
            <div data-nostr-divider=""
                 class=if cfg!(feature = "daisyui") { "divider text-xs opacity-50 my-1" } else { "" }>
                "More options"
            </div>

            // ── ncryptsec (NIP-49) ────────────────────────────────────────────
            <Show when=move || show_ncryptsec fallback=|| ()>
                <MethodButton
                    icon=icon_ncryptsec
                    title="Encrypted Key"
                    subtitle="Decrypt an ncryptsec1... key with your password"
                    badge=None
                    on_click=move || set_step.set(ModalStep::Ncryptsec)
                />
            </Show>

            // ── Read-Only ─────────────────────────────────────────────────────
            <Show when=move || show_readonly fallback=|| ()>
                <MethodButton
                    icon=icon_read_only
                    title="Read-Only"
                    subtitle="Paste an npub — browse without posting"
                    badge=None
                    on_click=move || set_step.set(ModalStep::ReadOnly)
                />
            </Show>

            // ── Raw nsec (feature-gated) ──────────────────────────────────────
            <Show when=move || show_nsec fallback=|| ()>
                <details data-nostr-advanced="">
                    <summary class=if cfg!(feature = "daisyui") { "text-xs opacity-50 cursor-pointer mt-1" } else { "" }>
                        "Advanced"
                    </summary>
                    <div class=if cfg!(feature = "daisyui") { "mt-2" } else { "" }>
                        {
                            #[cfg(feature = "insecure_nsec_input")]
                            {
                                view! {
                                    <MethodButton
                                        icon=icon_warning
                                        title="Secret Key"
                                        subtitle="⚠️ Paste nsec — not recommended for web use"
                                        badge=None
                                        on_click=move || set_step.set(ModalStep::RawNsecWarn)
                                    />
                                }.into_any()
                            }
                            #[cfg(not(feature = "insecure_nsec_input"))]
                            {
                                view! { <span/> }.into_any()
                            }
                        }
                    </div>
                </details>
            </Show>
        </div>
    }
}

// ─── Method Button ────────────────────────────────────────────────────────────

#[component]
fn MethodButton(
    icon: impl IntoView + 'static,
    title: &'static str,
    subtitle: &'static str,
    badge: Option<&'static str>,
    on_click: impl Fn() + 'static,
) -> impl IntoView {
    view! {
        <button
            data-nostr-method=""
            aria-label=format!("Login with {title}")
            class=if cfg!(feature = "daisyui") {
                "btn btn-ghost btn-block justify-start gap-3 text-left h-auto py-3"
            } else { "" }
            on:click=move |_| on_click()
        >
            <span data-nostr-method-icon="" class=if cfg!(feature = "daisyui") { "text-2xl" } else { "" }>
                {icon}
            </span>
            <span class=if cfg!(feature = "daisyui") { "flex-1 min-w-0" } else { "" }>
                <span
                    data-nostr-method-title=""
                    class=if cfg!(feature = "daisyui") { "block font-medium text-sm" } else { "" }
                >
                    {title}
                    {badge.map(|b| view! {
                        <span
                            data-nostr-badge=""
                            class=if cfg!(feature = "daisyui") { "badge badge-primary badge-sm ml-2" } else { "" }
                        >
                            {b}
                        </span>
                    })}
                </span>
                <span
                    data-nostr-method-subtitle=""
                    class=if cfg!(feature = "daisyui") { "block text-xs opacity-60 truncate" } else { "" }
                >
                    {subtitle}
                </span>
            </span>
            // Chevron
            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class=if cfg!(feature = "daisyui") { "opacity-40 shrink-0" } else { "" }>
                <path d="M9 18l6-6-6-6"/>
            </svg>
        </button>
    }
}

// ─── Icons (inline SVG) ───────────────────────────────────────────────────────

fn icon_extension() -> impl IntoView {
    view! { <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M9 3H5a2 2 0 0 0-2 2v4m6-6h10a2 2 0 0 1 2 2v4M9 3v18m0 0h10a2 2 0 0 0 2-2V9M9 21H5a2 2 0 0 1-2-2V9m0 0h18"/></svg> }
}
fn icon_passkey() -> impl IntoView {
    view! { <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg> }
}
fn icon_bunker() -> impl IntoView {
    view! { <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="5" y="11" width="14" height="10" rx="2"/><path d="M12 2a4 4 0 0 1 4 4v5H8V6a4 4 0 0 1 4-4z"/><circle cx="12" cy="16" r="1" fill="currentColor"/></svg> }
}
fn icon_amber() -> impl IntoView {
    view! { <svg data-nostr-icon-amber="" xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg> }
}
fn icon_read_only() -> impl IntoView {
    view! { <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg> }
}
fn icon_ncryptsec() -> impl IntoView {
    view! { <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg> }
}
#[cfg(feature = "insecure_nsec_input")]
fn icon_warning() -> impl IntoView {
    view! { <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg> }
}

// ─── Step 2a: Extension ───────────────────────────────────────────────────────

#[component]
fn StepExtension(
    on_auth: Callback<AuthResult>,
    set_error: WriteSignal<Option<String>>,
    set_step: WriteSignal<ModalStep>,
) -> impl IntoView {
    let (loading, set_loading) = signal(true);
    let (done, set_done) = signal(false);

    #[cfg(feature = "ssr")]
    let _ = (on_auth, set_done);

    // Shared login attempt — called from both the mount Effect and the "Try again" button.
    let attempt = move || {
        set_error.set(None);
        set_loading.set(true);
        #[cfg(not(feature = "ssr"))]
        spawn_local(async move {
            match Nip07Handle::get_public_key().await {
                Ok(handle) => {
                    set_done.set(true);
                    set_loading.set(false);
                    on_auth.run(AuthResult::Extension(handle));
                }
                Err(e) => {
                    set_error.set(Some(e.to_string()));
                    set_loading.set(false);
                }
            }
        });
        #[cfg(feature = "ssr")]
        set_loading.set(false);
    };

    // Trigger extension login immediately on mount
    Effect::new(move |_| attempt());

    view! {
        <div data-nostr-step="extension" class=if cfg!(feature = "daisyui") { "flex flex-col items-center gap-4 py-4" } else { "" }>
            <Show when=move || loading.get() fallback=|| ()>
                <span
                    aria-label="Waiting for extension…"
                    aria-live="polite"
                    class=if cfg!(feature = "daisyui") { "loading loading-spinner loading-lg" } else { "" }
                />
                <p class=if cfg!(feature = "daisyui") { "text-sm opacity-70" } else { "" }>
                    "Waiting for extension approval…"
                </p>
            </Show>
            <Show when=move || !loading.get() && !done.get() fallback=|| ()>
                <button
                    class=if cfg!(feature = "daisyui") { "btn btn-primary" } else { "" }
                    on:click=move |_| attempt()
                >
                    "Try again"
                </button>
                <button
                    class=if cfg!(feature = "daisyui") { "btn btn-ghost btn-sm" } else { "" }
                    on:click=move |_| set_step.set(ModalStep::MethodSelect)
                >
                    "Choose a different method"
                </button>
            </Show>
        </div>
    }
}

// ─── Step 2b: Bunker (NIP-46) ─────────────────────────────────────────────────

#[component]
fn StepBunker(
    on_auth: Callback<AuthResult>,
    set_error: WriteSignal<Option<String>>,
    platform: ReadSignal<Platform>,
    config: NostrAuthConfig,
) -> impl IntoView {
    let (uri, set_uri) = signal(String::new());
    let (loading, set_loading) = signal(false);
    let timeout = config.bunker_timeout_secs;

    #[cfg(feature = "ssr")]
    let _ = (on_auth, timeout);

    let connect = move || {
        let uri_val = uri.get();
        if uri_val.trim().is_empty() {
            set_error.set(Some("Please paste a bunker:// URI.".into()));
            return;
        }
        set_error.set(None);
        set_loading.set(true);
        #[cfg(not(feature = "ssr"))]
        spawn_local(async move {
            match BunkerSession::connect(&uri_val, timeout).await {
                Ok(session) => {
                    set_loading.set(false);
                    on_auth.run(AuthResult::Bunker(Box::new(session)));
                }
                Err(e) => {
                    set_error.set(Some(e.to_string()));
                    set_loading.set(false);
                }
            }
        });
        #[cfg(feature = "ssr")]
        set_loading.set(false);
    };

    view! {
        <div data-nostr-step="bunker" class=if cfg!(feature = "daisyui") { "flex flex-col gap-3" } else { "" }>
            <p class=if cfg!(feature = "daisyui") { "text-sm opacity-70" } else { "" }>
                "Paste a "
                <code class=if cfg!(feature = "daisyui") { "font-mono text-xs" } else { ""}>
                    "bunker://"
                </code>
                " URI from nsecBunker, Amber, or any NIP-46 signer."
            </p>

            // Amber tip — Android only
            <Show when=move || platform.get().is_android fallback=|| ()>
                <div
                    data-nostr-tip=""
                    class=if cfg!(feature = "daisyui") { "alert text-sm py-2" } else { "" }
                >
                    "Using Amber? Open Amber → Settings → Enable NIP-46 Bunker → copy the URI here."
                </div>
            </Show>

            <input
                type="text"
                placeholder="bunker://..."
                data-nostr-input="bunker-uri"
                class=if cfg!(feature = "daisyui") { "input input-bordered w-full font-mono text-sm" } else { "" }
                aria-label="Bunker URI"
                on:input=move |e| set_uri.set(event_target_value(&e))
                prop:value=move || uri.get()
                on:keydown={
                    move |e: web_sys::KeyboardEvent| {
                        if e.key() == "Enter" { connect(); }
                    }
                }
            />

            <button
                class=if cfg!(feature = "daisyui") { "btn btn-primary w-full" } else { "" }
                disabled=move || loading.get()
                on:click=move |_| connect()
            >
                <Show when=move || loading.get() fallback=|| view! { "Connect" }>
                    <span class=if cfg!(feature = "daisyui") { "loading loading-spinner loading-sm" } else { "" } />
                    "Connecting…"
                </Show>
            </button>
        </div>
    }
}

// ─── Step 2c: Passkey ─────────────────────────────────────────────────────────

#[component]
fn StepPasskey(
    on_auth: Callback<AuthResult>,
    set_error: WriteSignal<Option<String>>,
    config: NostrAuthConfig,
) -> impl IntoView {
    let (sub_step, set_sub_step) = signal(PasskeySubStep::Choose);
    // Store both in StoredValue so they're Copy-accessible across multiple Fn closures
    let rp_id = StoredValue::new(config.rp_id);
    let rp_name = StoredValue::new(config.rp_name);

    #[cfg(feature = "ssr")]
    let _ = (on_auth, rp_id, rp_name);

    view! {
        <div data-nostr-step="passkey" class=if cfg!(feature = "daisyui") { "flex flex-col gap-3" } else { "" }>
            <Show when=move || sub_step.get() == PasskeySubStep::Choose fallback=move || view! {
                <div class=if cfg!(feature = "daisyui") { "flex flex-col items-center gap-3 py-4" } else { "" }>
                    <span
                        aria-label="Waiting for biometric…"
                        aria-live="polite"
                        class=if cfg!(feature = "daisyui") { "loading loading-spinner loading-lg" } else { "" }
                    />
                    <p class=if cfg!(feature = "daisyui") { "text-sm opacity-70" } else { "" }>
                        "Complete the biometric prompt…"
                    </p>
                </div>
            }>
                <p class=if cfg!(feature = "daisyui") { "text-sm opacity-70" } else { "" }>
                    "Your Nostr identity is derived from your passkey using a deterministic algorithm.
                    The same passkey always produces the same Nostr key on any device."
                </p>

                <button
                    class=if cfg!(feature = "daisyui") { "btn btn-primary w-full" } else { "" }
                    on:click=move |_| {
                        set_sub_step.set(PasskeySubStep::Loading);
                        set_error.set(None);
                        #[cfg(not(feature = "ssr"))]
                        {
                            let rp = rp_id.get_value().clone().unwrap_or_else(|| {
                                web_sys::window()
                                    .and_then(|w| w.location().hostname().ok())
                                    .unwrap_or_else(|| "localhost".into())
                            });
                            let rp_name_val = rp_name.get_value();
                            spawn_local(async move {
                                match PasskeySession::create(&rp, &rp_name_val).await {
                                    Ok(session) => {
                                        on_auth.run(AuthResult::Passkey(session));
                                    }
                                    Err(e) => {
                                        set_error.set(Some(e.to_string()));
                                        set_sub_step.set(PasskeySubStep::Choose);
                                    }
                                }
                            });
                        }
                        #[cfg(feature = "ssr")]
                        set_sub_step.set(PasskeySubStep::Choose);
                    }
                >
                    "Create new Nostr identity"
                </button>

                <button
                    class=if cfg!(feature = "daisyui") { "btn btn-ghost btn-sm w-full" } else { "" }
                    on:click=move |_| {
                        set_sub_step.set(PasskeySubStep::Loading);
                        set_error.set(None);
                        #[cfg(not(feature = "ssr"))]
                        spawn_local(async move {
                            // Empty credential ID → browser presents all stored passkeys
                            match PasskeySession::authenticate(vec![]).await {
                                Ok(session) => {
                                    on_auth.run(AuthResult::Passkey(session));
                                }
                                Err(e) => {
                                    set_error.set(Some(e.to_string()));
                                    set_sub_step.set(PasskeySubStep::Choose);
                                }
                            }
                        });
                        #[cfg(feature = "ssr")]
                        set_sub_step.set(PasskeySubStep::Choose);
                    }
                >
                    "I already have a Nostr passkey — restore it"
                </button>
            </Show>
        </div>
    }
}

// ─── Step 2d: Read-Only ───────────────────────────────────────────────────────

#[component]
fn StepReadOnly(
    on_auth: Callback<AuthResult>,
    set_error: WriteSignal<Option<String>>,
) -> impl IntoView {
    let (input, set_input) = signal(String::new());

    let submit = move || {
        let val = input.get();
        match val.parse::<ReadOnlyHandle>() {
            Ok(handle) => {
                set_error.set(None);
                on_auth.run(AuthResult::ReadOnly(handle));
            }
            Err(e) => set_error.set(Some(e.to_string())),
        }
    };

    view! {
        <div data-nostr-step="readonly" class=if cfg!(feature = "daisyui") { "flex flex-col gap-3" } else { "" }>
            <div
                data-nostr-info=""
                class=if cfg!(feature = "daisyui") { "alert text-sm py-2" } else { "" }
            >
                "Read-only mode — you can browse but cannot post or send messages."
            </div>

            <input
                type="text"
                placeholder="npub1... or nprofile1... or 64-char hex"
                data-nostr-input="pubkey"
                class=if cfg!(feature = "daisyui") { "input input-bordered w-full font-mono text-sm" } else { "" }
                aria-label="Public key (npub, nprofile, or hex)"
                on:input=move |e| set_input.set(event_target_value(&e))
                prop:value=move || input.get()
                on:keydown=move |e: web_sys::KeyboardEvent| {
                    if e.key() == "Enter" { submit(); }
                }
            />

            <button
                class=if cfg!(feature = "daisyui") { "btn btn-primary w-full" } else { "" }
                on:click=move |_| submit()
            >
                "Browse read-only"
            </button>
        </div>
    }
}

// ─── Step 2e: ncryptsec (NIP-49) ─────────────────────────────────────────────

#[component]
fn StepNcryptsec(
    on_auth: Callback<AuthResult>,
    set_error: WriteSignal<Option<String>>,
) -> impl IntoView {
    let (ncryptsec, set_ncryptsec) = signal(String::new());
    let (password, set_password) = signal(String::new());
    let (loading, set_loading) = signal(false);

    #[cfg(feature = "ssr")]
    let _ = on_auth;

    let decrypt = move || {
        let nc = ncryptsec.get();
        let pw = password.get();
        if nc.trim().is_empty() {
            set_error.set(Some("Please paste your ncryptsec1... key.".into()));
            return;
        }
        if pw.is_empty() {
            set_error.set(Some("Please enter your password.".into()));
            return;
        }
        set_error.set(None);
        set_loading.set(true);
        // scrypt is CPU-intensive — run in spawn_local so the spinner renders first
        #[cfg(not(feature = "ssr"))]
        spawn_local(async move {
            // Yield one frame so the spinner renders before scrypt blocks the thread.
            let promise = js_sys::Promise::new(&mut |resolve, _| {
                let _ = web_sys::window()
                    .unwrap()
                    .set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, 16);
            });
            let _ = wasm_bindgen_futures::JsFuture::from(promise).await;

            match RawKeySession::from_ncryptsec(&nc, &pw) {
                Ok(session) => {
                    set_loading.set(false);
                    on_auth.run(AuthResult::Ncryptsec(session));
                }
                Err(e) => {
                    set_error.set(Some(e.to_string()));
                    set_loading.set(false);
                }
            }
        });
        #[cfg(feature = "ssr")]
        set_loading.set(false);
    };

    view! {
        <div data-nostr-step="ncryptsec" class=if cfg!(feature = "daisyui") { "flex flex-col gap-3" } else { "" }>
            <p class=if cfg!(feature = "daisyui") { "text-sm opacity-70" } else { "" }>
                "Paste your "
                <code class=if cfg!(feature = "daisyui") { "font-mono text-xs" } else { "" }>
                    "ncryptsec1..."
                </code>
                " encrypted key and enter your password to decrypt it."
            </p>

            <input
                type="text"
                placeholder="ncryptsec1..."
                data-nostr-input="ncryptsec"
                class=if cfg!(feature = "daisyui") { "input input-bordered w-full font-mono text-sm" } else { "" }
                aria-label="ncryptsec encrypted key"
                on:input=move |e| set_ncryptsec.set(event_target_value(&e))
                prop:value=move || ncryptsec.get()
            />

            <input
                type="password"
                placeholder="Password"
                data-nostr-input="ncryptsec-password"
                class=if cfg!(feature = "daisyui") { "input input-bordered w-full" } else { "" }
                aria-label="ncryptsec decryption password"
                on:input=move |e| set_password.set(event_target_value(&e))
                prop:value=move || password.get()
                on:keydown=move |e: web_sys::KeyboardEvent| {
                    if e.key() == "Enter" { decrypt(); }
                }
            />

            <button
                class=if cfg!(feature = "daisyui") { "btn btn-primary w-full" } else { "" }
                disabled=move || loading.get()
                on:click=move |_| decrypt()
            >
                <Show when=move || loading.get() fallback=|| view! { "Decrypt and sign in" }>
                    <span class=if cfg!(feature = "daisyui") { "loading loading-spinner loading-sm" } else { "" } />
                    "Decrypting…"
                </Show>
            </button>
        </div>
    }
}

// ─── Step 2f: Raw nsec (feature-gated) ───────────────────────────────────────

#[cfg(feature = "insecure_nsec_input")]
#[component]
fn StepRawNsecWarn(set_step: WriteSignal<ModalStep>) -> impl IntoView {
    view! {
        <div data-nostr-step="nsec-warn" class=if cfg!(feature = "daisyui") { "flex flex-col gap-4" } else { "" }>
            <div
                role="alert"
                data-nostr-warning=""
                class=if cfg!(feature = "daisyui") { "alert alert-error flex-col items-start" } else { "" }
            >
                <p class=if cfg!(feature = "daisyui") { "font-bold" } else { "" }>
                    "⚠️ This is not recommended"
                </p>
                <ul class=if cfg!(feature = "daisyui") { "list-disc list-inside text-sm mt-2 space-y-1 opacity-90" } else { "" }>
                    <li>"Any malicious script on this page can steal your key"</li>
                    <li>"Your clipboard may be monitored"</li>
                    <li>"Use a browser extension or passkey instead"</li>
                </ul>
            </div>
            <p class=if cfg!(feature = "daisyui") { "text-sm opacity-70" } else { "" }>
                "If you understand the risks and still want to proceed, tap below."
            </p>
            <button
                class=if cfg!(feature = "daisyui") { "btn btn-error w-full" } else { "" }
                on:click=move |_| set_step.set(ModalStep::RawNsec)
            >
                "I understand the risks — continue"
            </button>
        </div>
    }
}

#[cfg(feature = "insecure_nsec_input")]
#[component]
fn StepRawNsec(
    on_auth: Callback<AuthResult>,
    set_error: WriteSignal<Option<String>>,
) -> impl IntoView {
    let (nsec, set_nsec) = signal(String::new());

    let import = move || {
        let val = nsec.get();
        match RawKeySession::from_nsec_or_hex(&val) {
            Ok(session) => {
                // Zero the signal immediately
                set_nsec.set(String::new());
                set_error.set(None);
                on_auth.run(AuthResult::RawNsec(session));
            }
            Err(e) => set_error.set(Some(e.to_string())),
        }
    };

    view! {
        <div data-nostr-step="nsec" class=if cfg!(feature = "daisyui") { "flex flex-col gap-3" } else { "" }>
            <input
                type="password"
                autocomplete="off"
                placeholder="nsec1... or 64-char hex"
                data-nostr-input="nsec"
                class=if cfg!(feature = "daisyui") { "input input-bordered w-full font-mono text-sm" } else { "" }
                aria-label="Secret key (nsec or hex)"
                on:input=move |e| set_nsec.set(event_target_value(&e))
                prop:value=move || nsec.get()
                on:keydown=move |e: web_sys::KeyboardEvent| {
                    if e.key() == "Enter" { import(); }
                }
            />
            <button
                class=if cfg!(feature = "daisyui") { "btn btn-error w-full" } else { "" }
                on:click=move |_| import()
            >
                "Import secret key"
            </button>
        </div>
    }
}
