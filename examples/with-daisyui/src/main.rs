//! daisyUI example — requires Tailwind CSS v4 + daisyUI v5 in the build pipeline.
//! See style/tailwind.css and Trunk.toml for build configuration.

use leptos::prelude::*;
use leptos_nostr_auth::{use_nostr_auth, NostrAuthConfig, NostrAuthProvider};
use nostr::JsonUtil;

fn main() {
    console_error_panic_hook::set_once();
    leptos::mount::mount_to_body(|| view! { <App /> });
}

#[component]
fn App() -> impl IntoView {
    let config = NostrAuthConfig {
        persist_session: true,
        rp_id: Some("localhost".into()),
        rp_name: "My Nostr App".to_owned(),
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
    let (sign_output, set_sign_output) = signal(String::new());

    view! {
        <div class="card w-96 bg-base-200 shadow-xl">
            <div class="card-body">
                <h1 class="card-title">"My Nostr App"</h1>

                // Restoring indicator
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
                            <p class="text-sm opacity-70">"Connect your Nostr identity to get started."</p>
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

                        // Signing demo
                        <Show
                            when=move || auth.auth.get().is_some_and(|a| a.can_sign())
                            fallback=|| view! {
                                <p class="text-xs opacity-50">"(Read-only — cannot sign)"</p>
                            }
                        >
                            <button
                                class="btn btn-outline btn-xs w-full"
                                on:click=move |_| {
                                    if let Some(auth_result) = auth.auth.get() {
                                        let pubkey = auth_result.public_key();
                                        let unsigned = nostr::EventBuilder::new(
                                            nostr::Kind::TextNote,
                                            "Hello from leptos-nostr-auth!",
                                        )
                                        .build(pubkey);
                                        let event_json = unsigned.as_json();
                                        set_sign_output.set("Signing…".into());
                                        wasm_bindgen_futures::spawn_local(async move {
                                            match auth_result.sign_event(&event_json).await {
                                                Ok(signed) => {
                                                    let preview = &signed[..signed.len().min(60)];
                                                    set_sign_output.set(format!("{preview}…"));
                                                }
                                                Err(e) => set_sign_output.set(format!("Error: {e}")),
                                            }
                                        });
                                    }
                                }
                            >
                                "Sign test event"
                            </button>
                            <Show when=move || !sign_output.get().is_empty() fallback=|| ()>
                                <div class="bg-base-300 rounded p-2 font-mono text-xs break-all opacity-70">
                                    {move || sign_output.get()}
                                </div>
                            </Show>
                        </Show>
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
