//! Basic headless example — no CSS classes injected by the library.
//! Style via `data-nostr-*` attributes in your own CSS.

use leptos::prelude::*;
use leptos_nostr_auth::{use_nostr_auth, NostrAuthConfig, NostrAuthProvider};
use nostr::ToBech32;

fn main() {
    console_error_panic_hook::set_once();
    leptos::mount::mount_to_body(|| view! { <App /> });
}

#[component]
fn App() -> impl IntoView {
    let config = NostrAuthConfig {
        persist_session: true,
        rp_id: Some("localhost".into()),
        ..Default::default()
    };

    view! {
        <NostrAuthProvider config=config>
            <HomePage />
        </NostrAuthProvider>
    }
}

#[component]
fn HomePage() -> impl IntoView {
    let auth = use_nostr_auth();

    view! {
        <main style="font-family: sans-serif; max-width: 600px; margin: 4rem auto; padding: 1rem;">
            <h1>"Nostr Auth — Basic Example"</h1>

            <Show
                when=move || auth.is_authenticated.get()
                fallback=move || view! {
                    <p>"Not logged in."</p>
                    <button
                        style="padding: 0.5rem 1rem; cursor: pointer;"
                        on:click=move |_| auth.show_login.run(())
                    >
                        "Login with Nostr"
                    </button>
                }
            >
                <p>
                    "Logged in as: "
                    <code>
                        {move || auth.public_key.get()
                            .map(|pk| pk.to_bech32().unwrap_or_else(|_| pk.to_hex()))
                            .unwrap_or_default()}
                    </code>
                </p>
                <button
                    style="padding: 0.5rem 1rem; cursor: pointer;"
                    on:click=move |_| auth.logout.run(())
                >
                    "Logout"
                </button>
            </Show>
        </main>
    }
}
