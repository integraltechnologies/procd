//! A proc macro that, in the "rustc" phase, keeps the compiler itself running:
//! it executes inside rustc, so the witnessed pid is rustc's.
use proc_macro::TokenStream;
use std::time::Duration;

#[proc_macro]
pub fn stall(_: TokenStream) -> TokenStream {
    if std::env::var("PROCD_CARGO_PHASE").as_deref() == Ok("rustc") {
        if let Ok(dir) = std::env::var("PROCD_CARGO_WITNESS") {
            let pid = std::process::id();
            let tmp = std::path::Path::new(&dir).join(format!(".rustc.{pid}.tmp"));
            let fin = std::path::Path::new(&dir).join(format!("rustc.{pid}"));
            if std::fs::write(&tmp, format!("rustc {pid}\n")).is_ok() {
                let _ = std::fs::rename(&tmp, &fin);
            }
        }
        let secs = std::env::var("PROCD_CARGO_TTL")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(60)
            .min(300);
        std::thread::sleep(Duration::from_secs(secs));
    }
    TokenStream::new()
}
