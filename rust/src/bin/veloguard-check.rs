//! veloguard-check — `veloguard check-command` in Rust (src/cmdguard.rs): the
//! rules every agent's hook asks before each tool call. The `veloguard`
//! launcher hands `check-command` to it when it's installed root-owned.
use std::io::Write;

fn main() {
    let args: Vec<String> = std::env::args_os().skip(1).map(|a| a.to_string_lossy().into_owned()).collect();
    let (code, out) = veloguard::cmdguard::cli(&args, &mut veloguard::cmdguard::read_stdin);
    let _ = std::io::stdout().write_all(out.as_bytes());
    std::process::exit(code);
}
