# Code Signing Policy

This document establishes the official code-signing policy and security architecture for **SmartCacheCleaner**, maintained and published by **Pixel Craft Studios** in partnership with the **SignPath Foundation**.

---

## 1. Project Identification

- **Project Name:** SmartCacheCleaner
- **Repository:** [https://github.com/nisitha/SmartCacheCleaner](https://github.com/nisitha/SmartCacheCleaner)
- **Publisher / Maintainer:** Pixel Craft Studios ([https://www.pixelcraftlk.com](https://www.pixelcraftlk.com))
- **Primary Contact:** contact@pixelcraftlk.com / +94 78 767 6576
- **License:** [MIT License](LICENSE) (Open Source)

---

## 2. Scope of Signed Artifacts

Only production Windows binaries produced by the official CI release pipeline are eligible for Authenticode code signing:
1. **Standalone Portable Executable:** `SmartCacheCleaner.exe`
2. **Windows NSIS Setup Installer:** `SmartCacheCleaner_<version>_x64-setup.exe`

All signed artifacts are distributed exclusively through the official GitHub Releases page:
[https://github.com/nisitha/SmartCacheCleaner/releases](https://github.com/nisitha/SmartCacheCleaner/releases)

No unofficial, developer-local, or third-party binaries will ever be signed under this policy.

---

## 3. Build & Signing Provenance

1. **GitHub-Hosted CI Runners:**
   - All signed release artifacts are built strictly from public, tagged source code on clean, ephemeral `windows-latest` virtual machines managed by GitHub Actions.
   - Local developer machines and unverified forks cannot submit signing requests.

2. **Isolated Hardware Security Modules (HSM):**
   - Cryptographic signing keys and certificates are generated, secured, and stored exclusively within the SignPath Foundation's certified Hardware Security Modules (HSM).
   - Private signing keys are **never** held by developers, stored in this repository, exposed to runner environments, or accessible via environment variables.

3. **Tamper-Evident CI Pipeline:**
   - The signing request is submitted directly from GitHub Actions via the official `signpath/github-action-submit-signing-request` action using token authentication.
   - The artifact origin, Git commit SHA, and release tag are recorded in immutable audit logs provided by SignPath Foundation.

---

## 4. Security & Trust Boundaries

To guarantee software integrity for end users:

1. **Tag & Branch Protection:**
   - Only repository administrators and authorized maintainers have permission to push release tags (`v*.*.*`) or trigger the release pipeline (`release.yml`).
   - Pull requests from external contributors cannot access signing secrets and cannot initiate signing requests.

2. **Pre-Signing Security Verification:**
   - Every build must successfully compile and pass the entire Rust security test suite (`cargo test --manifest-path src-tauri/Cargo.toml`) before any signing request is submitted.
   - Any test failure (such as junction traversal, blocklist bypass, or path escaping) terminates the workflow immediately, preventing signing.

3. **Zero-Trust Runtime Architecture:**
   - The software runs 100% offline, initiates zero external network calls or tracking telemetry, and respects strict kernel-level blocklists defending personal files, system drivers, and credential vaults.

---

## 5. Revocation & Incident Response

In the improbable event of a compromised release token or security flaw:
- The SignPath Foundation will be immediately notified to revoke the affected certificate or reject pending signing requests.
- The compromised release will be retracted from GitHub Releases, and an advisory will be published in the GitHub Security Advisories tab.
