use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

fn wardn() -> Command {
    Command::cargo_bin("wardn").unwrap()
}

#[test]
fn test_help() {
    wardn()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Credential isolation for AI agents"));
}

#[test]
fn test_version() {
    wardn()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("wardn"));
}

#[test]
fn test_vault_help() {
    wardn()
        .args(["vault", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("create"))
        .stdout(predicate::str::contains("set"))
        .stdout(predicate::str::contains("get"))
        .stdout(predicate::str::contains("list"))
        .stdout(predicate::str::contains("rotate"))
        .stdout(predicate::str::contains("remove"));
}

#[test]
fn test_vault_create_and_list() {
    let dir = TempDir::new().unwrap();
    let vault_path = dir.path().join("test.enc");

    // Create vault
    wardn()
        .args(["vault", "create", "--vault", vault_path.to_str().unwrap()])
        .env("WARDN_PASSPHRASE", "testpass")
        .assert()
        .success()
        .stdout(predicate::str::contains("vault created"));

    // List empty vault
    wardn()
        .args(["vault", "list", "--vault", vault_path.to_str().unwrap()])
        .env("WARDN_PASSPHRASE", "testpass")
        .assert()
        .success()
        .stdout(predicate::str::contains("vault is empty"));
}

#[test]
fn test_vault_set_and_get() {
    let dir = TempDir::new().unwrap();
    let vault_path = dir.path().join("test.enc");

    // Create vault
    wardn()
        .args(["vault", "create", "--vault", vault_path.to_str().unwrap()])
        .env("WARDN_PASSPHRASE", "testpass")
        .assert()
        .success();

    // Set credential
    wardn()
        .args(["vault", "set", "MY_KEY", "--vault", vault_path.to_str().unwrap()])
        .env("WARDN_PASSPHRASE", "testpass")
        .env("WARDN_VALUE", "secret-value-123")
        .assert()
        .success()
        .stdout(predicate::str::contains("stored MY_KEY"));

    // Get placeholder (never the real value)
    wardn()
        .args(["vault", "get", "MY_KEY", "--vault", vault_path.to_str().unwrap()])
        .env("WARDN_PASSPHRASE", "testpass")
        .assert()
        .success()
        .stdout(predicate::str::starts_with("wdn_placeholder_"))
        .stdout(predicate::str::contains("secret-value-123").not());

    // List shows credential name
    wardn()
        .args(["vault", "list", "--vault", vault_path.to_str().unwrap()])
        .env("WARDN_PASSPHRASE", "testpass")
        .assert()
        .success()
        .stdout(predicate::str::contains("MY_KEY"))
        .stdout(predicate::str::contains("secret-value-123").not());
}

#[test]
fn test_vault_rotate() {
    let dir = TempDir::new().unwrap();
    let vault_path = dir.path().join("test.enc");

    wardn()
        .args(["vault", "create", "--vault", vault_path.to_str().unwrap()])
        .env("WARDN_PASSPHRASE", "testpass")
        .assert()
        .success();

    wardn()
        .args(["vault", "set", "KEY", "--vault", vault_path.to_str().unwrap()])
        .env("WARDN_PASSPHRASE", "testpass")
        .env("WARDN_VALUE", "old-value")
        .assert()
        .success();

    wardn()
        .args(["vault", "rotate", "KEY", "--vault", vault_path.to_str().unwrap()])
        .env("WARDN_PASSPHRASE", "testpass")
        .env("WARDN_VALUE", "new-value")
        .assert()
        .success()
        .stdout(predicate::str::contains("rotated KEY"));
}

#[test]
fn test_vault_remove() {
    let dir = TempDir::new().unwrap();
    let vault_path = dir.path().join("test.enc");

    wardn()
        .args(["vault", "create", "--vault", vault_path.to_str().unwrap()])
        .env("WARDN_PASSPHRASE", "testpass")
        .assert()
        .success();

    wardn()
        .args(["vault", "set", "KEY", "--vault", vault_path.to_str().unwrap()])
        .env("WARDN_PASSPHRASE", "testpass")
        .env("WARDN_VALUE", "val")
        .assert()
        .success();

    wardn()
        .args(["vault", "remove", "KEY", "--vault", vault_path.to_str().unwrap()])
        .env("WARDN_PASSPHRASE", "testpass")
        .assert()
        .success()
        .stdout(predicate::str::contains("removed KEY"));
}

#[test]
fn test_vault_remove_nonexistent_fails() {
    let dir = TempDir::new().unwrap();
    let vault_path = dir.path().join("test.enc");

    wardn()
        .args(["vault", "create", "--vault", vault_path.to_str().unwrap()])
        .env("WARDN_PASSPHRASE", "testpass")
        .assert()
        .success();

    wardn()
        .args(["vault", "remove", "NOPE", "--vault", vault_path.to_str().unwrap()])
        .env("WARDN_PASSPHRASE", "testpass")
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found"));
}

#[test]
fn test_vault_create_already_exists_fails() {
    let dir = TempDir::new().unwrap();
    let vault_path = dir.path().join("test.enc");

    wardn()
        .args(["vault", "create", "--vault", vault_path.to_str().unwrap()])
        .env("WARDN_PASSPHRASE", "testpass")
        .assert()
        .success();

    // Second create should fail
    wardn()
        .args(["vault", "create", "--vault", vault_path.to_str().unwrap()])
        .env("WARDN_PASSPHRASE", "testpass")
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists"));
}

#[test]
fn test_vault_wrong_passphrase_fails() {
    let dir = TempDir::new().unwrap();
    let vault_path = dir.path().join("test.enc");

    wardn()
        .args(["vault", "create", "--vault", vault_path.to_str().unwrap()])
        .env("WARDN_PASSPHRASE", "correct")
        .assert()
        .success();

    wardn()
        .args(["vault", "list", "--vault", vault_path.to_str().unwrap()])
        .env("WARDN_PASSPHRASE", "wrong")
        .assert()
        .failure();
}

#[test]
fn test_migrate_dry_run() {
    let dir = TempDir::new().unwrap();
    std::fs::write(
        dir.path().join(".env"),
        "OPENAI_KEY=sk-proj-abc123def456ghi789\n",
    )
    .unwrap();

    wardn()
        .args([
            "migrate",
            "--source", "directory",
            "--path", dir.path().to_str().unwrap(),
            "--dry-run",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("SECURITY AUDIT"))
        .stdout(predicate::str::contains("OPENAI_KEY"))
        .stdout(predicate::str::contains("DRY RUN"));
}

#[test]
fn test_migrate_empty_directory() {
    let dir = TempDir::new().unwrap();

    wardn()
        .args([
            "migrate",
            "--source", "directory",
            "--path", dir.path().to_str().unwrap(),
            "--dry-run",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("No exposed credentials found"));
}

#[test]
fn test_serve_mcp_without_agent_fails() {
    let dir = TempDir::new().unwrap();
    let vault_path = dir.path().join("test.enc");

    wardn()
        .args(["vault", "create", "--vault", vault_path.to_str().unwrap()])
        .env("WARDN_PASSPHRASE", "testpass")
        .assert()
        .success();

    wardn()
        .args(["serve", "--mcp", "--vault", vault_path.to_str().unwrap()])
        .env("WARDN_PASSPHRASE", "testpass")
        .assert()
        .failure()
        .stderr(predicate::str::contains("--agent is required"));
}

#[test]
fn test_get_placeholder_never_leaks_value() {
    let dir = TempDir::new().unwrap();
    let vault_path = dir.path().join("test.enc");

    wardn()
        .args(["vault", "create", "--vault", vault_path.to_str().unwrap()])
        .env("WARDN_PASSPHRASE", "testpass")
        .assert()
        .success();

    wardn()
        .args(["vault", "set", "SECRET", "--vault", vault_path.to_str().unwrap()])
        .env("WARDN_PASSPHRASE", "testpass")
        .env("WARDN_VALUE", "super-secret-api-key-12345")
        .assert()
        .success();

    // Get placeholder — verify it NEVER contains the real value
    let output = wardn()
        .args(["vault", "get", "SECRET", "--vault", vault_path.to_str().unwrap()])
        .env("WARDN_PASSPHRASE", "testpass")
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();

    assert!(stdout.contains("wdn_placeholder_"));
    assert!(!stdout.contains("super-secret-api-key-12345"));
    assert!(!stderr.contains("super-secret-api-key-12345"));
}
