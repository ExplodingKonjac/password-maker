# Password Maker

Password Maker is an offline Rust desktop password generator and encrypted vault.
It runs on Windows, macOS, and Linux.

## Security model

The generator uses a per-vault random 256-bit generation key. The key, saved
keywords, and generator options are encrypted by the hyper password.

For a keyword and its options, the application derives a deterministic seed with
keyed BLAKE3 and generates characters with portable ChaCha20Rng. The algorithm
version, alphabet version, Unicode normalization, class guarantees, and golden
vectors are versioned so the same vault reproduces the same password.

Vault files use Argon2id key derivation and XChaCha20-Poly1305 authenticated
encryption. Passwords are never logged. The hyper password has no recovery path;
keep an encrypted backup and use a strong passphrase.

## Build and test

```text
cargo run
cargo test --all-targets
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
```

The first launch asks for a hyper password. After unlocking, use **Generate**
for deterministic passwords, **Vault** to save keyword entries, and **Settings**
for auto-lock, encrypted backups, and password rotation.

Generated passwords are copied to the system clipboard only after an explicit
action. Password Maker clears a copied value after 30 seconds when the clipboard
still contains that value, and clears it when the vault locks.

## Distribution

The application is distributed under GPLv3-or-later. Slint is used under its
GPLv3 option; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
