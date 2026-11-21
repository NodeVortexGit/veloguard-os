//! veloguard-mcp — the VeloGuard MCP server (stdio). See src/mcp.rs.
fn main() {
    if std::env::args().nth(1).as_deref() == Some("--version") {
        println!("veloguard-mcp {} (rust)", veloguard::VERSION);
        return;
    }
    veloguard::mcp::serve();
}
