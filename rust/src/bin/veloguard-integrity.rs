//! veloguard-integrity check | update — the guard checks its own files. See src/integrity.rs.
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    std::process::exit(veloguard::integrity::main(&args));
}
