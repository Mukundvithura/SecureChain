# SecureChain CI/CD Setup & Secrets Guide

This document provides complete instructions for configuring GitHub repository settings, environment secrets, and branch protection rules for SecureChain.

---

## 1. Required GitHub Secrets and Variables

### Security Scanning
- `GITHUB_TOKEN`: Provided automatically by GitHub Actions with default read permissions.

### Staging Deployment (`staging` Environment)
Configured under **Settings > Environments > staging**:

| Secret Name | Description | Example / Format |
| --- | --- | --- |
| `STAGING_HOST` | Hostname or IPv4 address of the target Linux sensor host. | `ec2-54-123-45-67.compute-1.amazonaws.com` |
| `STAGING_USER` | SSH user with required execution privileges. | `ubuntu` or `ec2-user` |
| `STAGING_SSH_KEY` | Private SSH Key (ed25519 or RSA) for authentication. | `-----BEGIN OPENSSH PRIVATE KEY-----...` |

---

## 2. Branch Protection Rules

To safeguard the primary branch (`main`), configure the following branch protection rules under **Settings > Branches**:

1. **Require a pull request before merging**:
   - Require approvals: minimum 1 reviewer.
   - Dismiss stale pull request approvals when new commits are pushed.
2. **Require status checks to pass before merging**:
   - `Code Formatting (Nightly rustfmt)`
   - `Clippy Linter (Userspace & Common)`
   - `Unit Tests (Userspace)`
   - `Userspace & eBPF Compilation`
   - `Secret Leak Detection (Gitleaks)`
   - `Rust Dependency Security Audit`
3. **Require branches to be up to date before merging**.
4. **Do not allow bypassing the above settings**.

---

## 3. GitHub Environment Protection (`staging`)

Create an environment named `staging` under **Settings > Environments**:
- Enable **Required reviewers** if manual sign-off is desired prior to staging rollout.
- Set deployment branch policies to restrict staging deployments to tags or the `main` branch.
