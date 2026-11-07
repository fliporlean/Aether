//! nway.rs — Phase B ingest for the encrypted ALFA config.
//!
//! WHAT THIS DOES
//!
//! The server config travels DOWN ENCRYPTED and is opened ONLY in native. For
//! the ALFA path, that native core is this binary (libaether.so). Java hands us
//! nothing but ciphertext; this module opens it here, inside aether's own
//! process, and never lets the plaintext — or the per-device key `ak` — back
//! into Java.
//!
//! HOW IT PLUGS IN
//!
//! aether is already fully env-driven: cli::parse_args turns every `--flag` into
//! `std::env::set_var("AETHER_*", value)`, and the rest of run() reads those
//! vars. So all this module has to do is set the same AETHER_* vars that the
//! flags would have set — before run_with() reads them.
//!
//! The entry point is apply_encrypted_config(), called once at the very top of
//! run_with() (before cli::parse_args). It is a NO-OP unless AETHER_ENC_BLOB is
//! set, so a normal launch (flags/env as today) is completely unaffected.
//!
//! INPUT (all passed by the Java launcher as env, none secret except the blob
//! which is ciphertext):
//!   AETHER_ENC_BLOB  base64 GCM envelope of the ALFA config JSON (ciphertext)
//!   AETHER_ENC_DIR   the app's filesDir (where the device key store lives)
//!   AETHER_ENC_UUID  the device uuid (ANDROID_ID) the store is bound to
//!
//! It decrypts by calling libEncryption.so's `nway_decrypt_config(enc,dir,uuid)`
//! through dlopen — the same C entry libv2ray uses — so `ak` stays inside
//! libEncryption and only the plaintext JSON comes back.
//!
//! SCOPE (this version): the `aether` field only — the tunnel shape, exactly as
//! the host app's AetherLink parses it today (ported 1:1). The other config
//! fields (exit_node / register_upstream / split_server / ladder-wide psiphon)
//! are handled on the Java + libv2ray side, because they route through Xray's
//! loopback / the registration pass and must not be guessed here.

use std::collections::HashMap;
use std::ffi::{CStr, CString};

use libc::{c_char, c_void, dlopen, dlsym, RTLD_NOW};

const SCHEME: &str = "aether://";

// ---- the semi-python fingerprint's cipher list -----------------------------
// Byte-for-byte AlfaSettings.TLS_CIPHERS (the list measured working from Iran).
// Kept here so "fingerprint=semi-python" expands to exactly what the Java side
// does. If AlfaSettings.TLS_CIPHERS ever changes, change it here too.
const TLS_CIPHERS_SEMI_PYTHON: &str = concat!(
    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:",
    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:",
    "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:",
    "ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:",
    "ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256"
);

const TLS_CIPHERS_CHROME: &str = "ALL:!aPSK:!ECDSA+SHA1:!3DES";

const TLS_CIPHERS_FIREFOX: &str = concat!(
    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:",
    "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:",
    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:",
    "ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:",
    "AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA"
);

const TLS_CIPHERS_GO: &str = concat!(
    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:",
    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:",
    "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:",
    "ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:",
    "ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA"
);

// name -> (ciphers, grease_on)
fn fingerprint_row(name: &str) -> Option<(&'static str, bool)> {
    match name {
        "chrome" => Some((TLS_CIPHERS_CHROME, true)),
        "firefox" => Some((TLS_CIPHERS_FIREFOX, false)),
        "semi-python" => Some((TLS_CIPHERS_SEMI_PYTHON, false)),
        "go" => Some((TLS_CIPHERS_GO, false)),
        _ => None,
    }
}

const PROTOCOLS: [&str; 4] = ["masque", "wg", "gool", "mim"];
const SCANS: [&str; 5] = ["turbo", "balanced", "thorough", "verified", "ironclad"];
const NOIZE: [&str; 6] = ["off", "light", "firewall", "balanced", "gfw", "aggressive"];
const TRANSPORTS: [&str; 2] = ["h2", "h3"];
const PSIPHON: [&str; 4] = ["off", "chain", "reverse", "only"];
const PSIPHON_MODES: [&str; 3] = ["auto", "cdn", "direct"];
const CDN_SETS: [&str; 9] = [
    "cloudflare", "fastly", "cloudfront", "psiphon-akamai", "psiphon-bunny",
    "vercel", "github", "curated-fronting", "legacy-android-overrides",
];

// Keys that are the module's plumbing (ports, identity paths) or belong in a
// field of their own (exit node, key server, split). A link carrying one is
// refused whole, exactly as AetherLink does, so a mistake is loud not silent.
const REFUSED: [(&str, &str); 11] = [
    ("listen_port", "the bind port is fixed: Xray dials it"),
    ("bind", "the bind port is fixed: Xray dials it"),
    ("psiphon_bind", "the psiphon bind port is managed with the bind port"),
    ("upstream", "use the exit-node field, which routes through Xray"),
    ("psiphon_bin", "the psiphon binary path belongs to the module"),
    ("psiphon_dir", "the psiphon state path belongs to the module"),
    ("api_address", "set it in a field of its own, not the profile link"),
    ("exit_node", "a share link does not nest inside another link's query"),
    ("register", "use the register-upstream field"),
    ("register_upstream", "use the register-upstream field"),
    ("split_server", "use the split-server field"),
];

// Flags a raw command line may not carry (same reasons as REFUSED).
const REFUSED_FLAGS: [(&str, &str); 12] = [
    ("--bind", "the bind port is fixed: Xray dials it"),
    ("--psiphon-bind", "the psiphon bind port is managed with the bind port"),
    ("--tor-bind", "the tor bind port is managed with the bind port"),
    ("--http-proxy", "an extra listener could take a port this module uses"),
    ("--psiphon-http", "an extra listener could take a port this module uses"),
    ("--tor-http", "an extra listener could take a port this module uses"),
    ("--upstream", "use the exit-node field, which routes through Xray"),
    ("--psiphon-bin", "the psiphon binary path belongs to the module"),
    ("--psiphon-dir", "the psiphon state path belongs to the module"),
    ("--api-address", "set it in a field of its own"),
    ("--register", "registration is a separate pass this module runs itself"),
    ("--masque-config", "the identity file path belongs to the module"),
];

// =============================================================================
//  entry
// =============================================================================

/// Open the encrypted ALFA config (if any) and set the AETHER_* env the tunnel
/// needs. No-op when AETHER_ENC_BLOB is unset, so a normal launch is untouched.
/// Must be called before cli::parse_args / any AETHER_* read in run_with().
pub fn apply_encrypted_config() {
    let blob = std::env::var("AETHER_ENC_BLOB").unwrap_or_default();
    if blob.trim().is_empty() {
        return;
    }
    let dir = std::env::var("AETHER_ENC_DIR").unwrap_or_default();
    let uuid = std::env::var("AETHER_ENC_UUID").unwrap_or_default();

    let mut plain = match decrypt(&blob, &dir, &uuid) {
        Some(p) => p,
        None => {
            eprintln!("[nway] could not open the encrypted ALFA config");
            return;
        }
    };

    // Drop the ciphertext from the environment now that it is opened; nothing
    // downstream needs it, and a child (psiphon) should not inherit it.
    std::env::remove_var("AETHER_ENC_BLOB");

    match apply_json(&plain) {
        Ok(n) => eprintln!("[nway] applied encrypted ALFA config ({} vars set)", n),
        Err(e) => eprintln!("[nway] {}", e),
    }

    // Best-effort wipe of the plaintext we held.
    wipe(&mut plain);
}

fn wipe(s: &mut String) {
    unsafe {
        for b in s.as_mut_vec().iter_mut() {
            *b = 0;
        }
    }
    s.clear();
}

// =============================================================================
//  decrypt via libEncryption.so (same C entry libv2ray uses)
// =============================================================================

type DecryptFn = unsafe extern "C" fn(*const c_char, *const c_char, *const c_char) -> *const c_char;
type FreeFn = unsafe extern "C" fn(*const c_char);

fn decrypt(blob: &str, dir: &str, uuid: &str) -> Option<String> {
    unsafe {
        // Prefer the absolute path the launcher passes (AETHER_ENC_LIB), which the app knows
        // (its nativeLibraryDir); fall back to the soname so a plain run still works.
        let libname = std::env::var("AETHER_ENC_LIB")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "libEncryption.so".to_string());
        let soname = CString::new(libname.clone()).ok()?;
        let handle: *mut c_void = dlopen(soname.as_ptr(), RTLD_NOW);
        if handle.is_null() {
            eprintln!("[nway] dlopen({}) failed", libname);
            return None;
        }

        let dsym = CString::new("nway_decrypt_config").ok()?;
        let dptr = dlsym(handle, dsym.as_ptr());
        if dptr.is_null() {
            eprintln!("[nway] nway_decrypt_config not found in libEncryption.so");
            return None;
        }
        let decrypt_fn: DecryptFn = std::mem::transmute(dptr);

        let fsym = CString::new("nway_free").ok()?;
        let fptr = dlsym(handle, fsym.as_ptr());

        let c_blob = CString::new(blob).ok()?;
        let c_dir = CString::new(dir).ok()?;
        let c_uuid = CString::new(uuid).ok()?;

        let out = decrypt_fn(c_blob.as_ptr(), c_dir.as_ptr(), c_uuid.as_ptr());
        if out.is_null() {
            return None;
        }
        let plain = CStr::from_ptr(out).to_string_lossy().into_owned();

        if !fptr.is_null() {
            let free_fn: FreeFn = std::mem::transmute(fptr);
            free_fn(out);
        }
        // handle intentionally left open for the process lifetime.
        Some(plain)
    }
}

// =============================================================================
//  JSON -> AETHER_* env
// =============================================================================

fn apply_json(plain: &str) -> Result<usize, String> {
    let v: serde_json::Value =
        serde_json::from_str(plain).map_err(|e| format!("ALFA config is not JSON: {e}"))?;
    let obj = v
        .as_object()
        .ok_or_else(|| "ALFA config is not a JSON object".to_string())?;

    // This version wires the `aether` field (the tunnel shape). The other
    // fields are applied on the Java + libv2ray side.
    let aether = match obj.get("aether") {
        Some(a) => a,
        None => return Ok(0),
    };
    apply_aether(aether)
}

fn apply_aether(val: &serde_json::Value) -> Result<usize, String> {
    match val {
        serde_json::Value::String(s) => {
            let t = s.trim();
            let low = t.to_lowercase();
            if low.starts_with(SCHEME) {
                let pairs = parse_link(t)?;
                flush(&pairs);
                Ok(pairs.len())
            } else if low.starts_with("--") || low.starts_with("aether ") || low == "aether" {
                parse_raw_command(t)
            } else {
                Err("'aether' is neither an aether:// link nor an aether command line".to_string())
            }
        }
        // Flat map: keys are AETHER_* names, set straight through.
        serde_json::Value::Object(map) => {
            let mut pairs: Vec<(String, String)> = Vec::new();
            for (k, v) in map {
                let val = match v {
                    serde_json::Value::String(s) => s.clone(),
                    serde_json::Value::Bool(b) => (if *b { "1" } else { "0" }).to_string(),
                    serde_json::Value::Number(n) => n.to_string(),
                    _ => continue,
                };
                pairs.push((k.clone(), val));
            }
            flush(&pairs);
            Ok(pairs.len())
        }
        _ => Err("'aether' must be a string (link) or an object (flat map)".to_string()),
    }
}

fn flush(pairs: &[(String, String)]) {
    for (k, v) in pairs {
        std::env::set_var(k, v);
    }
}

// =============================================================================
//  the aether:// link  (a 1:1 port of AetherLink.parse)
//
//  Collected into a Vec first and only flushed by the caller on success, so a
//  bad value leaves no half-applied config — exactly AetherLink's atomicity.
// =============================================================================

fn parse_link(link: &str) -> Result<Vec<(String, String)>, String> {
    let mut out: Vec<(String, String)> = Vec::new();

    let mut s = link[SCHEME.len()..].to_string();
    if let Some(h) = s.find('#') {
        s.truncate(h);
    }
    let mut query = String::new();
    if let Some(q) = s.find('?') {
        query = s[q + 1..].to_string();
        s.truncate(q);
    }
    if let Some(at) = s.rfind('@') {
        s = s[at + 1..].to_string();
    }
    while s.ends_with('/') {
        s.pop();
    }
    let peer = s.trim().to_string();

    let p = query_map(&query);

    for (k, why) in REFUSED.iter() {
        if p.contains_key(*k) {
            return Err(format!("{} cannot be set from a link: {}", k, why));
        }
    }

    // --- peer ---------------------------------------------------------------
    if !peer.is_empty() {
        if !looks_like_endpoint(&peer) {
            return Err(format!("'{}' is not host:port", peer));
        }
        out.push(("AETHER_PEER".into(), peer.clone()));
    }

    // --- protocol (with the wg-over-masque and gool-classic rewrites) -------
    let mut proto = p
        .get("protocol")
        .map(|v| v.trim().to_lowercase())
        .filter(|v| !v.is_empty());
    if proto.as_deref() == Some("wg-over-masque") {
        proto = Some("gool".to_string());
    }
    let mut effective_proto = String::new();
    match proto.as_deref() {
        Some("gool-classic") => out.push(("AETHER_GOOL_MODE".into(), "classic".into())),
        Some(pr) => {
            if !PROTOCOLS.contains(&pr) {
                return Err(format!(
                    "protocol={} is not one of: {}",
                    pr,
                    PROTOCOLS.join(", ")
                ));
            }
            out.push(("AETHER_PROTOCOL".into(), pr.to_string()));
            effective_proto = pr.to_string();
        }
        None => {}
    }

    // --- scan (stealth -> verified) -----------------------------------------
    let mut scan = p
        .get("scan")
        .map(|v| v.trim().to_lowercase())
        .filter(|v| !v.is_empty());
    if scan.as_deref() == Some("stealth") {
        scan = Some("verified".to_string());
    }
    if let Some(sc) = scan {
        if !SCANS.contains(&sc.as_str()) {
            return Err(format!("scan={} is not one of: {}", sc, SCANS.join(", ")));
        }
        out.push(("AETHER_SCAN".into(), sc));
    }

    // --- noize (auto -> omit) -----------------------------------------------
    let mut noize = p
        .get("noize")
        .map(|v| v.trim().to_lowercase())
        .filter(|v| !v.is_empty());
    if noize.as_deref() == Some("auto") {
        noize = None;
    }
    if let Some(nz) = noize {
        if !NOIZE.contains(&nz.as_str()) {
            return Err(format!("noize={} is not one of: {}", nz, NOIZE.join(", ")));
        }
        out.push(("AETHER_NOIZE".into(), nz));
    }

    // --- ip (dual -> both) --------------------------------------------------
    if let Some(ip) = p
        .get("ip")
        .map(|v| v.trim().to_lowercase())
        .filter(|v| !v.is_empty())
    {
        let v = if ip == "dual" { "both".to_string() } else { ip };
        if !["v4", "v6", "both"].contains(&v.as_str()) {
            return Err(format!("ip={} is not v4, v6 or both", v));
        }
        out.push(("AETHER_IP".into(), v));
    }

    // --- transport (h2 is a flag; h3 is the silent default) -----------------
    if let Some(tr) = p
        .get("transport")
        .map(|v| v.trim().to_lowercase())
        .filter(|v| !v.is_empty())
    {
        if !TRANSPORTS.contains(&tr.as_str()) {
            return Err(format!("transport={} is not h2 or h3", tr));
        }
        if tr == "h2" {
            out.push(("AETHER_MASQUE_HTTP2".into(), "1".into()));
        }
    }

    // --- the ClientHello ----------------------------------------------------
    if let Some(sni) = p.get("sni").map(|v| v.trim().to_string()).filter(|v| !v.is_empty()) {
        out.push(("AETHER_MASQUE_SNI".into(), sni));
    }

    if let Some(fp) = p
        .get("fingerprint")
        .map(|v| v.trim().to_lowercase())
        .filter(|v| !v.is_empty())
    {
        match fingerprint_row(&fp) {
            Some((ciphers, grease_on)) => {
                out.push(("AETHER_TLS_CIPHERS".into(), ciphers.to_string()));
                if !grease_on {
                    out.push(("AETHER_DISABLE_GREASE".into(), "1".into()));
                }
            }
            None => {
                return Err(format!(
                    "fingerprint={} is not chrome, firefox, semi-python or go",
                    fp
                ))
            }
        }
    }

    if flag(&p, "fragment") {
        out.push(("AETHER_MASQUE_H2_FRAGMENT".into(), "1".into()));
        copy(&p, "fragment_size", &mut out, "AETHER_MASQUE_H2_FRAGMENT_SIZE");
        copy(&p, "fragment_delay", &mut out, "AETHER_MASQUE_H2_FRAGMENT_DELAY");
    }

    if flag(&p, "ech") {
        out.push(("AETHER_ECH".into(), "auto".into()));
        copy(&p, "ech_dns", &mut out, "AETHER_ECH_DNS");
        copy(&p, "ech_domain", &mut out, "AETHER_ECH_DOMAIN");
    }

    // --- what the tunnel does once it is up ---------------------------------
    copy(&p, "dns", &mut out, "AETHER_DNS");
    copy(&p, "exit_loc", &mut out, "AETHER_EXIT_LOC");

    // --- psiphon ------------------------------------------------------------
    if let Some(psi) = p
        .get("psiphon")
        .map(|v| v.trim().to_lowercase())
        .filter(|v| !v.is_empty())
    {
        if !PSIPHON.contains(&psi.as_str()) {
            return Err(format!(
                "psiphon={} is not off, chain, reverse or only",
                psi
            ));
        }
        match psi.as_str() {
            "reverse" => out.push(("AETHER_PSIPHON".into(), "reverse".into())),
            "only" => out.push(("AETHER_PSIPHON".into(), "only".into())),
            "chain" => out.push(("AETHER_PSIPHON".into(), "chain".into())),
            _ => {} // off: nothing
        }
    }
    if let Some(pm) = p
        .get("psiphon_mode")
        .map(|v| v.trim().to_lowercase())
        .filter(|v| !v.is_empty())
    {
        if !PSIPHON_MODES.contains(&pm.as_str()) {
            return Err(format!(
                "psiphon_mode={} is not one of: {}",
                pm,
                PSIPHON_MODES.join(", ")
            ));
        }
        out.push(("AETHER_PSIPHON_MODE".into(), pm));
    }
    copy(&p, "cdn_ips", &mut out, "AETHER_PSIPHON_CDN_IPS");
    copy(&p, "cdn_sni", &mut out, "AETHER_PSIPHON_CDN_SNI");
    if let Some(sets_raw) = p
        .get("cdn_sets")
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
    {
        match checked_list(&sets_raw, &CDN_SETS) {
            Some(joined) => out.push(("AETHER_PSIPHON_CDN_SETS".into(), joined)),
            None => {
                return Err(format!(
                    "cdn_sets={} names an unknown edge list; known: {}",
                    sets_raw,
                    CDN_SETS.join(", ")
                ))
            }
        }
    }
    copy(&p, "region", &mut out, "AETHER_PSIPHON_REGION");

    // --- two-hop endpoints (the flag pair depends on the protocol) ----------
    let (outer_env, inner_env) = match effective_proto.as_str() {
        "mim" => ("AETHER_MIM_OUTER_PEER", "AETHER_MIM_INNER_PEER"),
        "gool" => ("AETHER_PEER", "AETHER_GOOL_INNER"),
        _ => ("AETHER_WIW_OUTER_PEER", "AETHER_WIW_INNER_PEER"),
    };
    copy(&p, "outer", &mut out, outer_env);
    copy(&p, "inner", &mut out, inner_env);

    // timeout is the module's rung clock, not an aether var — not set here.
    // tor_* and anything unknown are dropped, as AetherLink does.

    Ok(out)
}

// A raw aether command line: reuse aether's own parser to turn it into env,
// after refusing the flags that are the module's plumbing.
fn parse_raw_command(s: &str) -> Result<usize, String> {
    let mut body = s.trim().to_string();
    if body.to_lowercase().starts_with("aether") {
        body = body[6..].trim().to_string();
    }
    if body.is_empty() {
        return Err("an empty aether command line".to_string());
    }
    let tokens = tokenize(&body);
    if tokens.is_empty() {
        return Err("an empty aether command line".to_string());
    }
    for arg in &tokens {
        for (flag, why) in REFUSED_FLAGS.iter() {
            if arg == flag {
                return Err(format!("{} cannot be set from a profile: {}", flag, why));
            }
        }
    }
    let n = tokens.len();
    crate::cli::parse_args(tokens).map_err(|e| format!("{e}"))?;
    Ok(n)
}

// =============================================================================
//  helpers (ports of the AetherLink plumbing)
// =============================================================================

fn copy(p: &HashMap<String, String>, param: &str, out: &mut Vec<(String, String)>, env: &str) {
    if let Some(v) = p.get(param) {
        let t = v.trim();
        if !t.is_empty() {
            out.push((env.to_string(), t.to_string()));
        }
    }
}

fn flag(p: &HashMap<String, String>, param: &str) -> bool {
    match p.get(param) {
        Some(v) => {
            let t = v.trim().to_lowercase();
            t == "1" || t == "true" || t == "yes" || t == "on"
        }
        None => false,
    }
}

fn checked_list(raw: &str, allowed: &[&str]) -> Option<String> {
    let mut parts: Vec<String> = Vec::new();
    for part in raw
        .trim()
        .to_lowercase()
        .split(|c: char| c == ',' || c == ';' || c.is_whitespace())
    {
        if part.is_empty() {
            continue;
        }
        if !allowed.contains(&part) {
            return None;
        }
        parts.push(part.to_string());
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(","))
    }
}

fn looks_like_endpoint(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let colon = match s.rfind(':') {
        Some(c) => c,
        None => return false,
    };
    if colon == 0 || colon == s.len() - 1 {
        return false;
    }
    let host = &s[..colon];
    if host.is_empty() || host.contains(' ') {
        return false;
    }
    match s[colon + 1..].parse::<i64>() {
        Ok(port) => port > 0 && port <= 65535,
        Err(_) => false,
    }
}

// Last value wins; names lower-cased; values percent-decoded. '+' is left
// alone (it is legal in a base64 ECH key and in a cipher list).
fn query_map(query: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    if query.is_empty() {
        return out;
    }
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = match pair.find('=') {
            Some(eq) => (&pair[..eq], &pair[eq + 1..]),
            None => (pair, ""),
        };
        let key = decode(k).trim().to_lowercase();
        if !key.is_empty() {
            out.insert(key, decode(v));
        }
    }
    out
}

fn decode(s: &str) -> String {
    if !s.contains('%') {
        return s.to_string();
    }
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0usize;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let hi = (b[i + 1] as char).to_digit(16);
            let lo = (b[i + 2] as char).to_digit(16);
            if let (Some(h), Some(l)) = (hi, lo) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

// Splits a command line on whitespace, respecting single and double quotes.
fn tokenize(s: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut quote: char = '\0';
    let mut any = false;
    for c in s.chars() {
        if quote != '\0' {
            if c == quote {
                quote = '\0';
            } else {
                cur.push(c);
            }
            continue;
        }
        if c == '"' || c == '\'' {
            quote = c;
            any = true;
            continue;
        }
        if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
            if !cur.is_empty() || any {
                out.push(std::mem::take(&mut cur));
                any = false;
            }
            continue;
        }
        cur.push(c);
    }
    if !cur.is_empty() || any {
        out.push(cur);
    }
    out
}
