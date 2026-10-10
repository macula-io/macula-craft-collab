//! Live citizen sign-in probe: creates a real join session against the
//! realm's portal (the link a person opens or scans), polls it once, and
//! prints the state — never the credential material.
//!
//! Usage: sign_in_probe <realm_name> [slug]

use macula_craft_collab::{Identity, realm};

fn main() {
    let realm_name = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: sign_in_probe <realm_name> [slug]");
        std::process::exit(2);
    });
    let slug = std::env::args().nth(2).unwrap_or_else(|| "sign-in-probe".into());
    let dir = macula_craft_collab::identity::craft_identity_dir().unwrap_or_else(|| std::env::temp_dir().join("craft-sign-in-probe"));
    let identity =
        Identity::load_or_create_with(macula_rust::profile::Profile::PqHybrid, &slug, "Sign In Probe", None, Some(&dir)).expect("identity");
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0);
    let base = realm::session::realm_base_url(&realm_name);
    println!("portal: {base}");
    match realm::session::create_session(&realm_name, &base, &identity, now) {
        Ok(created) => {
            println!("session: {}", created.session_id);
            println!("join_url: {}", created.join_url);
            println!("expires_at: {}", created.expires_at);
            match realm::session::poll_session(&base, &created.session_id) {
                Ok(realm::SessionStatus::Pending { expires_at }) => {
                    println!("status: pending (expires {expires_at}) — a person confirms next")
                }
                Ok(realm::SessionStatus::Confirmed(_)) => println!("status: confirmed"),
                Ok(realm::SessionStatus::Expired) => println!("status: expired"),
                Ok(realm::SessionStatus::Error(e)) => println!("status: error {e}"),
                Err(e) => println!("poll failed: {e}"),
            }
        }
        Err(e) => {
            println!("create failed: {e}");
            std::process::exit(1);
        }
    }
}
