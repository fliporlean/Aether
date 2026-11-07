//! nway_psiphon.rs
//!
//! Phase B, psiphon half. The ALFA server config travels down ENCRYPTED and is
//! opened only inside libaether.so (see nway.rs). nway.rs wires the `aether`
//! field (the tunnel shape); THIS module wires every TOP-LEVEL psiphon field of
//! that same config into the `AETHER_PSIPHON_*` environment that psiphon.rs
//! reads - so the encrypted (secure) path has the exact same psiphon reach as
//! the `--psiphon*` flags the Java side builds on the plaintext path.
//!
//! Parity map (ALFA config field  ->  AETHER_* env  <-  Java equivalent):
//!
//!     psiphon_position     -> AETHER_PSIPHON           (--psiphon / -reverse / -only)
//!     psiphon_mode         -> AETHER_PSIPHON_MODE      (--psiphon-mode)
//!     psiphon_region       -> AETHER_PSIPHON_REGION    (--psiphon-region)
//!     psiphon_cdn_ips      -> AETHER_PSIPHON_CDN_IPS   (--psiphon-cdn-ips)
//!     psiphon_cdn_sni      -> AETHER_PSIPHON_CDN_SNI   (--psiphon-cdn-sni)
//!     psiphon_cdn_sets     -> AETHER_PSIPHON_CDN_SETS  (--psiphon-cdn-sets)
//!     psiphon_server_entries -> AETHER_PSIPHON_SERVER_ENTRIES (--psiphon-server-entries, a file)
//!     psiphon_config         -> AETHER_PSIPHON_CONFIG         (--psiphon-config, a file)
//!
//! This is the complete set the Java AetherExecutor.addPsiphonSettings +
//! buildPsiphonArgs produce from AlfaOptions. Three AlfaOptions fields are
//! deliberately NOT here because they are not aether's to read:
//!
//!   - psiphon_list_upstream / psiphon_list_* timings: these drive the Java
//!     PsiphonList (fetching/caching psiphon's signed server list). aether
//!     fetches that list itself from its built-in RemoteServerListURLs (through
//!     the WARP tunnel in chain mode), so there is no aether env for them.
//!   - register_via_psiphon: a registration-flow switch, handled where
//!     registration is driven, not here.
//!
//! One thing the Java path adds that cannot come from the blob is
//! `DNSResolverAlternateServers` (AlfaSettings.PSIPHON_DNS_RESOLVERS, an app
//! constant, injected into the psiphon config). If that is wanted in the secure
//! path it belongs on the Java side (write a psiphon config and point
//! AETHER_PSIPHON_CONFIG at it), not here - a blob field it is not.
//!
//! psiphon.rs value mapping this module targets (mode()):
//!     ""/"0"/"off"/"false"/"no" => Off
//!     "reverse"/"rev"/"warp-over-psiphon" => Reverse
//!     "only"/"alone"/"psiphon-only"/"direct" => Only
//!     anything else (incl. "chain") => Chain
//! so the position string is passed through lower-cased and aether interprets it.

use serde_json::{Map, Value};

/// Apply every top-level psiphon field of the decrypted ALFA config to the
/// environment, and return how many variables were set (for the "N vars set"
/// line). Call this AFTER apply_aether, so the backend's top-level decision
/// overrides anything a ladder rung or an in-link `psiphon=` left behind
/// (the backend's config is authoritative for ALFA).
pub fn apply_psiphon(obj: &Map<String, Value>) -> usize {
    let mut n = 0usize;

    // Position. Set UNCONDITIONALLY, "off" when absent/blank, so the backend's
    // choice wins over any psiphon flag a rung or the aether link set first.
    let pos = obj
        .get("psiphon_position")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_lowercase();
    std::env::set_var(
        "AETHER_PSIPHON",
        if pos.is_empty() { "off" } else { pos.as_str() },
    );
    n += 1;

    // The rest are optional: set only when the backend sent them, so an absent
    // field leaves aether on its own default (same as the Java path omitting
    // the flag).
    n += set_str(obj, "psiphon_mode", "AETHER_PSIPHON_MODE");
    n += set_str(obj, "psiphon_region", "AETHER_PSIPHON_REGION");
    n += set_list(obj, "psiphon_cdn_ips", "AETHER_PSIPHON_CDN_IPS");
    n += set_list(obj, "psiphon_cdn_sni", "AETHER_PSIPHON_CDN_SNI");
    n += set_list(obj, "psiphon_cdn_sets", "AETHER_PSIPHON_CDN_SETS");

    // The two that can carry credentials. aether takes each as a FILE PATH, and
    // the Java path writes the text to a file for exactly this reason. Here the
    // text is in the (already decrypted, in-process) blob, so it is written to a
    // file beside the key store and the env points at the path - it never
    // becomes anything Java can read.
    n += write_file_opt(
        obj,
        "psiphon_server_entries",
        "AETHER_PSIPHON_SERVER_ENTRIES",
        "nway_psiphon_entries.dat",
    );
    n += write_file_opt(
        obj,
        "psiphon_config",
        "AETHER_PSIPHON_CONFIG",
        "nway_psiphon_config.json",
    );

    n
}

/// A string field -> env, trimmed; skipped (0) when absent or blank.
fn set_str(obj: &Map<String, Value>, key: &str, env: &str) -> usize {
    if let Some(s) = obj.get(key).and_then(|v| v.as_str()) {
        let t = s.trim();
        if !t.is_empty() {
            std::env::set_var(env, t);
            return 1;
        }
    }
    0
}

/// A JSON array of strings, OR a single comma/space string, -> a comma-joined
/// env value (what aether's cdn_candidates splits on). Skipped (0) when empty.
fn set_list(obj: &Map<String, Value>, key: &str, env: &str) -> usize {
    let parts: Vec<String> = match obj.get(key) {
        Some(Value::Array(arr)) => arr
            .iter()
            .filter_map(|v| v.as_str())
            .flat_map(split_fields)
            .collect(),
        Some(Value::String(s)) => split_fields(s.as_str()),
        _ => return 0,
    };
    if parts.is_empty() {
        return 0;
    }
    std::env::set_var(env, parts.join(","));
    1
}

/// Splits on commas and whitespace, dropping blanks - matches how the Java side
/// explodes these lists and how aether re-splits them.
fn split_fields(s: &str) -> Vec<String> {
    s.split(|c: char| c == ',' || c.is_whitespace())
        .map(|p| p.trim())
        .filter(|p| !p.is_empty())
        .map(|p| p.to_string())
        .collect()
}

/// Writes a text field to <AETHER_ENC_DIR>/<filename> and points `env` at the
/// path. Skipped (0) when the field is absent/blank or the write fails - aether
/// then falls back to its built-in default (list download / built-in
/// credentials), exactly as the Java path does when it cannot write the cache.
fn write_file_opt(obj: &Map<String, Value>, key: &str, env: &str, filename: &str) -> usize {
    let content = match obj.get(key).and_then(|v| v.as_str()) {
        Some(s) if !s.trim().is_empty() => s,
        _ => return 0,
    };
    let dir = std::env::var("AETHER_ENC_DIR").unwrap_or_default();
    let path = if dir.is_empty() {
        filename.to_string()
    } else {
        format!("{}/{}", dir.trim_end_matches('/'), filename)
    };
    if std::fs::write(&path, content).is_err() {
        eprintln!("[nway] could not write {env}");
        return 0;
    }
    std::env::set_var(env, &path);
    1
}
