// In the "build" phase the build script keeps running with an attached child
// and a detached, orphaned daemon, the way long build scripts that start
// servers or compilers do.
include!("src/role.rs");

fn main() {
    let exe = std::env::current_exe().expect("build script path");
    run_role(&exe);
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var("PROCD_CARGO_PHASE").as_deref() == Ok("build") {
        let _mid = spawn_role(&exe, "build-mid", false);
        let _child = spawn_role(&exe, "build-child", false);
        witness("build-script");
        linger();
    }
}
