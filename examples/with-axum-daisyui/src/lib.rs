// #[component] generates exhaustive props structs we cannot control.
#![allow(clippy::exhaustive_structs)]
use leptos::prelude::*;
use leptos_nostr_auth::{use_nostr_auth, NostrAuthConfig, NostrAuthProvider};

#[cfg(feature = "hydrate")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn hydrate() {
    console_error_panic_hook::set_once();
    leptos::mount::hydrate_body(App);
}

/// HTML shell — server renders this as the full outer document.
pub fn shell(options: LeptosOptions) -> impl IntoView {
    view! {
        <!DOCTYPE html>
        <html lang="en" data-theme="dark">
            <head>
                <meta charset="utf-8"/>
                <meta name="viewport" content="width=device-width, initial-scale=1"/>
                <title>"Nostr Auth — Axum SSR + daisyUI"</title>
                <HydrationScripts options/>
                <link rel="stylesheet" href="/pkg/with-axum-daisyui.css"/>
            </head>
            <body>
                <App/>
            </body>
        </html>
    }
}

#[component]
pub fn App() -> impl IntoView {
    let config = NostrAuthConfig {
        persist_session: true,
        rp_id: Some("localhost".into()),
        rp_name: "My Nostr App".to_owned(),
        ..Default::default()
    };
    view! {
        <NostrAuthProvider config=config>
            <div class="min-h-screen bg-base-100 flex items-center justify-center">
                <HomePage/>
            </div>
        </NostrAuthProvider>
    }
}

#[component]
fn HomePage() -> impl IntoView {
    let auth = use_nostr_auth();

    view! {
        <div class="card w-96 bg-base-200 shadow-xl">
            <div class="card-body">
                <h1 class="card-title">"My Nostr App"</h1>
                <p class="text-xs opacity-50">"SSR + daisyUI example"</p>

                <Show when=move || auth.is_restoring.get() fallback=|| ()>
                    <div class="flex items-center gap-2 text-sm opacity-60">
                        <span class="loading loading-spinner loading-xs"/>
                        "Restoring session…"
                    </div>
                </Show>

                <Show
                    when=move || auth.is_authenticated.get()
                    fallback=move || view! {
                        <Show when=move || !auth.is_restoring.get() fallback=|| ()>
                            <p class="text-sm opacity-70">
                                "Connect your Nostr identity to get started."
                            </p>
                            <div class="card-actions justify-end mt-2">
                                <button
                                    class="btn btn-primary"
                                    on:click=move |_| auth.show_login.run(())
                                >
                                    "Login with Nostr"
                                </button>
                            </div>
                        </Show>
                    }
                >
                    <div class="text-sm space-y-2">
                        <div class="flex items-center gap-2">
                            <span class="badge badge-success gap-2">
                                <div class="w-2 h-2 rounded-full bg-success-content"/>
                                "Connected"
                            </span>
                            <span class="text-xs opacity-60">
                                {move || auth.auth.get().map_or("", |a| a.method_name())}
                            </span>
                        </div>
                        <div class="bg-base-300 rounded-lg p-3 font-mono text-xs break-all">
                            {move || auth.npub.get().unwrap_or_default()}
                        </div>
                    </div>
                    <div class="card-actions justify-end mt-2">
                        <button
                            class="btn btn-ghost btn-sm"
                            on:click=move |_| auth.logout.run(())
                        >
                            "Disconnect"
                        </button>
                    </div>
                </Show>
            </div>
        </div>
    }
}
