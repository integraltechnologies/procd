// Shared by build.rs, the helper binary and the integration test via include!.
// Every fixture process records "<role> <pid>" in PROCD_CARGO_WITNESS and lives
// at most PROCD_CARGO_TTL seconds (default 60, capped at 300), so a broken
// supervisor can never leave an unbounded process behind.
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

#[allow(dead_code)]
fn witness(role: &str) {
    if let Ok(dir) = std::env::var("PROCD_CARGO_WITNESS") {
        let pid = std::process::id();
        let tmp = Path::new(&dir).join(format!(".{role}.{pid}.tmp"));
        let fin = Path::new(&dir).join(format!("{role}.{pid}"));
        if std::fs::write(&tmp, format!("{role} {pid}\n")).is_ok() {
            let _ = std::fs::rename(&tmp, &fin);
        }
    }
}

#[allow(dead_code)]
fn ttl() -> Duration {
    let secs = std::env::var("PROCD_CARGO_TTL")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(60)
        .min(300);
    Duration::from_secs(secs)
}

#[allow(dead_code)]
fn linger() -> ! {
    std::thread::sleep(ttl());
    std::process::exit(0)
}

#[cfg(unix)]
extern "C" {
    fn setsid() -> i32;
}

/// Start `exe` in `role`. `detached` = a new session on Unix, and
/// DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP on Windows.
#[allow(dead_code)]
fn spawn_role(exe: &Path, role: &str, detached: bool) -> std::io::Result<Child> {
    let mut c = Command::new(exe);
    c.env("PROCD_FIXTURE_ROLE", role)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if detached {
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            unsafe {
                c.pre_exec(|| {
                    setsid();
                    Ok(())
                });
            }
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            c.creation_flags(0x0000_0008 | 0x0000_0200);
        }
    }
    c.spawn()
}

/// If this process was started in a fixture role, play it and never return.
#[allow(dead_code)]
fn run_role(exe: &Path) {
    let role = match std::env::var("PROCD_FIXTURE_ROLE") {
        Ok(r) => r,
        Err(_) => return,
    };
    match role.as_str() {
        "child" => {
            let _ = spawn_role(exe, "grandchild", false);
            witness("child");
            linger()
        }
        mid if mid.ends_with("-mid") => {
            // launch a detached daemon, then exit at once: the daemon is orphaned
            let daemon = format!("{}-daemon", &mid[..mid.len() - 4]);
            let ok = spawn_role(exe, &daemon, true).is_ok();
            if ok {
                witness(mid);
            }
            std::process::exit(if ok { 0 } else { 1 })
        }
        other => {
            witness(other);
            linger()
        }
    }
}
