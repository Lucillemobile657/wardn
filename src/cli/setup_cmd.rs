use std::path::Path;

use anyhow::{Context, Result};

/// Run `wardn setup claude-code` — registers wardn as an MCP server in Claude Code.
pub fn run(vault_path: &Path) -> Result<()> {
    let wardn_bin = find_wardn_binary()?;
    let vault_abs = std::fs::canonicalize(vault_path)
        .unwrap_or_else(|_| vault_path.to_path_buf());

    println!("Setting up wardn for Claude Code...\n");

    // Check if claude CLI exists
    let claude_check = std::process::Command::new("claude")
        .arg("--version")
        .output();

    if claude_check.is_err() || !claude_check.unwrap().status.success() {
        eprintln!("error: 'claude' CLI not found. Install Claude Code first:");
        eprintln!("  https://claude.ai/code");
        std::process::exit(1);
    }

    // Register wardn as MCP server
    let status = std::process::Command::new("claude")
        .args([
            "mcp", "add",
            "--transport", "stdio",
            "--scope", "user",
            "wardn",
            "--",
            &wardn_bin,
            "serve",
            "--mcp",
            "--agent", "claude-code",
            "--vault", vault_abs.to_str().unwrap_or("~/.vibeguard/vault.enc"),
        ])
        .status()
        .context("failed to run 'claude mcp add'")?;

    if !status.success() {
        eprintln!("failed to register wardn MCP server");
        std::process::exit(1);
    }

    println!("\nwardn registered as MCP server in Claude Code.");
    println!();
    println!("Claude Code now has these tools:");
    println!("  get_credential_ref  — get a placeholder token for a credential");
    println!("  list_credentials    — list available credentials");
    println!("  check_rate_limit    — check remaining quota");
    println!();
    println!("When Claude needs an API key, it will call get_credential_ref");
    println!("and receive a placeholder token (never the real key).");
    println!();
    println!("Verify with:");
    println!("  claude mcp list");

    Ok(())
}

/// Find the wardn binary path.
fn find_wardn_binary() -> Result<String> {
    // Check if we're running from cargo install
    if let Ok(current_exe) = std::env::current_exe() {
        if current_exe.file_name().map(|f| f == "wardn").unwrap_or(false) {
            return Ok(current_exe.to_string_lossy().to_string());
        }
    }

    // Check PATH
    let which = std::process::Command::new("which")
        .arg("wardn")
        .output();

    if let Ok(output) = which {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                return Ok(path);
            }
        }
    }

    // Fallback
    Ok("wardn".to_string())
}
