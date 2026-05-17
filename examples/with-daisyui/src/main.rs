//! daisyUI example — requires Tailwind CSS v4 + daisyUI v5 in the build pipeline.
//! See style/tailwind.css and Trunk.toml for build configuration.

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
        rp_name: "My Nostr App",
        ..Default::default()
    };

    view! {
        <NostrAuthProvider config=config>
            <div class="min-h-screen bg-base-100 flex items-center justify-center" data-theme="dark">
                <HomePage />
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

                <Show
                    when=move || auth.is_authenticated.get()
                    fallback=move || view! {
                        <p class="text-sm opacity-70">"Connect your Nostr identity to get started."</p>
                        <div class="card-actions justify-end mt-2">
                            <button
                                class="btn btn-primary"
                                on:click=move |_| auth.show_login.run(())
                            >
                                "Login with Nostr"
                            </button>
                        </div>
                    }
                >
                    <div class="text-sm">
                        <span class="badge badge-success gap-2 mb-3">
                            <div class="w-2 h-2 rounded-full bg-success-content"/>
                            "Connected"
                        </span>
                        <div class="bg-base-300 rounded-lg p-3 font-mono text-xs break-all">
                            {move || auth.public_key.get()
                                .map(|pk| pk.to_bech32().unwrap_or_else(|_| pk.to_hex()))
                                .unwrap_or_default()}
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
