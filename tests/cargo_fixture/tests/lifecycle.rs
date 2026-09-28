// In the "test" phase this test keeps running with a child, a grandchild and a
// detached, orphaned daemon -- a test that starts helper processes and hangs.
include!("../src/role.rs");

#[test]
fn long_running_task() {
    assert_eq!(procd_fixture::answer(), 42);
    if std::env::var("PROCD_CARGO_PHASE").as_deref() != Ok("test") {
        return;
    }
    let helper = Path::new(env!("CARGO_BIN_EXE_helper"));
    let _child = spawn_role(helper, "child", false);
    let _mid = spawn_role(helper, "test-mid", false);
    witness("test");
    std::thread::sleep(ttl());
}
