use std::path::Path;

use anyhow::{Context, Result};

use super::SetupCommands;

pub fn run(cmd: &SetupCommands, vault_path: &Path) -> Result<()> {
    match cmd {
        SetupCommands::ClaudeCode => setup_claude_code(vault_path),
        SetupCommands::Cursor => setup_cursor(vault_path),
    }
}

/// Register wardn as an MCP server in Claude Code via `claude mcp add`.
fn setup_claude_code(vault_path: &Path) -> Result<()> {
    let wardn_bin = find_wardn_binary()?;
    let vault_abs = std::fs::canonicalize(vault_path)
        .unwrap_or_else(|_| vault_path.to_path_buf());
    let vault_str = vault_abs.to_str().unwrap_or("~/.vibeguard/vault.enc");

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
            "--vault", vault_str,
        ])
        .status()
        .context("failed to run 'claude mcp add'")?;

    if !status.success() {
        eprintln!("failed to register wardn MCP server");
        std::process::exit(1);
    }

    print_success("Claude Code", "claude mcp list");
    Ok(())
}

/// Register wardn as an MCP server in Cursor via ~/.cursor/mcp.json.
fn setup_cursor(vault_path: &Path) -> Result<()> {
    let wardn_bin = find_wardn_binary()?;
    let vault_abs = std::fs::canonicalize(vault_path)
        .unwrap_or_else(|_| vault_path.to_path_buf());
    let vault_str = vault_abs.to_str().unwrap_or("~/.vibeguard/vault.enc");

    println!("Setting up wardn for Cursor...\n");

    let cursor_dir = dirs_cursor();
    let mcp_path = cursor_dir.join("mcp.json");

    // Read existing config or create new
    let mut config: serde_json::Value = if mcp_path.exists() {
        let content = std::fs::read_to_string(&mcp_path)
            .context("failed to read ~/.cursor/mcp.json")?;
        if content.trim().is_empty() {
            serde_json::json!({ "mcpServers": {} })
        } else {
            serde_json::from_str(&content)
                .context("failed to parse ~/.cursor/mcp.json")?
        }
    } else {
        std::fs::create_dir_all(&cursor_dir)
            .context("failed to create ~/.cursor/")?;
        serde_json::json!({ "mcpServers": {} })
    };

    // Add wardn server entry
    let servers = config
        .as_object_mut()
        .context("invalid mcp.json format")?
        .entry("mcpServers")
        .or_insert_with(|| serde_json::json!({}));

    servers.as_object_mut()
        .context("mcpServers must be an object")?
        .insert("wardn".to_string(), serde_json::json!({
            "command": wardn_bin,
            "args": ["serve", "--mcp", "--agent", "cursor", "--vault", vault_str]
        }));

    // Write back
    let formatted = serde_json::to_string_pretty(&config)
        .context("failed to serialize mcp.json")?;
    std::fs::write(&mcp_path, formatted)
        .context("failed to write ~/.cursor/mcp.json")?;

    println!("wrote {}", mcp_path.display());
    print_success("Cursor", "Cursor Settings → Features → MCP");
    Ok(())
}

fn print_success(tool: &str, verify_cmd: &str) {
    println!("\nwardn registered as MCP server in {tool}.");
    println!();
    println!("MCP tools available:");
    println!("  get_credential_ref  — get a placeholder token for a credential");
    println!("  list_credentials    — list available credentials");
    println!("  check_rate_limit    — check remaining quota");
    println!();
    println!("When the agent needs an API key, it calls get_credential_ref");
    println!("and receives a placeholder token (never the real key).");
    println!();
    println!("Verify with:");
    println!("  {verify_cmd}");
}

/// Find the wardn binary path.
fn find_wardn_binary() -> Result<String> {
    if let Ok(current_exe) = std::env::current_exe() {
        if current_exe.file_name().map(|f| f == "wardn").unwrap_or(false) {
            return Ok(current_exe.to_string_lossy().to_string());
        }
    }

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

    Ok("wardn".to_string())
}

fn dirs_cursor() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_default();
    std::path::PathBuf::from(home).join(".cursor")
}
