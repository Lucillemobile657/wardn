pub mod migrate_cmd;
pub mod serve_cmd;
pub mod vault_cmd;

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(
    name = "wardn",
    about = "Credential isolation for AI agents",
    version,
    propagate_version = true
)]
pub struct Cli {
    /// Path to the vault file
    #[arg(long, global = true, default_value = "~/.vibeguard/vault.enc")]
    pub vault: String,

    /// Path to the wardn config file (TOML)
    #[arg(long, global = true)]
    pub config: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Manage the encrypted credential vault
    Vault {
        #[command(subcommand)]
        command: VaultCommands,
    },

    /// Start the wardn proxy server
    Serve(ServeArgs),

    /// Scan for exposed credentials and migrate them
    Migrate(MigrateArgs),
}

#[derive(Subcommand)]
pub enum VaultCommands {
    /// Create a new encrypted vault
    Create,

    /// Store a credential in the vault
    Set {
        /// Credential name (e.g. OPENAI_KEY)
        key: String,
    },

    /// Get the placeholder token for a credential (never the real value)
    Get {
        /// Credential name
        key: String,

        /// Agent identity for the placeholder
        #[arg(long, default_value = "cli")]
        agent: String,
    },

    /// List all stored credentials (names only, no values)
    List,

    /// Rotate a credential value (placeholder stays the same)
    Rotate {
        /// Credential name to rotate
        key: String,
    },

    /// Remove a credential from the vault
    Remove {
        /// Credential name to remove
        key: String,
    },
}

#[derive(Parser)]
pub struct ServeArgs {
    /// Host to bind to
    #[arg(long, default_value = "127.0.0.1")]
    pub host: String,

    /// Port to listen on
    #[arg(long, default_value_t = 7777)]
    pub port: u16,

    /// Also start the MCP server over stdio
    #[arg(long)]
    pub mcp: bool,

    /// Agent identity for MCP server (required with --mcp)
    #[arg(long)]
    pub agent: Option<String>,
}

#[derive(Parser)]
pub struct MigrateArgs {
    /// Source system to scan
    #[arg(long, value_enum, default_value = "claude-code")]
    pub source: MigrateSourceArg,

    /// Directory to scan (for --source directory)
    #[arg(long)]
    pub path: Option<PathBuf>,

    /// Audit only — don't migrate credentials
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Clone, ValueEnum)]
pub enum MigrateSourceArg {
    ClaudeCode,
    OpenClaw,
    Directory,
}
