include!("../role.rs");

fn main() {
    let exe = std::env::current_exe().expect("helper path");
    run_role(&exe);
}
