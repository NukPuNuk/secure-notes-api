# Incident Playbook: Leaked Secret

**Use when:** a credential (database password, API key, token, signing key, cloud
credential) has been committed to a repository, printed in CI logs, or otherwise exposed.

**Core rule: rotate first.** Once a secret has been pushed, assume it has been copied.
Public repositories are scraped for credentials within minutes. Deleting the secret in a
new commit, or even rewriting history, does **not** make it safe. Only revoking it does.

| | |
|---|---|
| Severity default | **High**; **Critical** if the secret can reach ePHI or production |
| Owner | Security on-call (incident commander) + owner of the leaked credential |
| Related | [threat-model.md](threat-model.md) · [triage.md, F-4](triage.md#f-4-hardcoded-database-admin-password) |

---

## Phase 1: Detect and triage (first 15 minutes)

**Detection sources in this repo:**
- GitHub **push protection** (blocks known provider tokens before they reach the remote)
- GitHub **secret scanning** alerts
- **Gitleaks** in CI, including the custom `connection-string-password` rule
- A human report (code review, private vulnerability report via `SECURITY.md`)

**Confirm and classify:**
1. Is it a real credential, or a test fixture / placeholder? (In Phase 5.4 the value was
   deliberately fake. Treat a real-looking value as real until proven otherwise.)
2. What is it, and what can it reach? (DB admin? read-only API key? signing key?)
3. Where was it exposed? Public repo, private repo, CI logs, a PR comment, a fork?
4. When? First commit time = start of the exposure window.

Open an incident ticket, record the above, and assign an incident commander.

## Phase 2: Contain (immediately, before investigating)

1. **Revoke or rotate the secret at its source** (DB password change, key revocation in the
   provider console, Key Vault secret rotation, signing-key rollover).
2. **Deploy the new secret** through the proper store (Key Vault / User Secrets), never back into the repo.
3. **Invalidate derived sessions/tokens** if the secret was a signing key or a long-lived token.
4. If rotation would cause an outage, the incident commander decides. The default is to rotate
   anyway: downtime is recoverable, a breach is not.

## Phase 3: Investigate and scope

1. **Review access logs for the exposure window** (first commit time → rotation time):
   DB/server logs, cloud audit logs, Key Vault access logs, API gateway logs.
   Look for unfamiliar IPs, unusual hours, bulk reads, new accounts or permissions.
2. **Blast radius:** what could this credential reach? For a DB admin account (`sa`): every
   database on the server, so **all ePHI** in it.
3. **Was ePHI accessed?** If yes, or if you can't rule it out → **Phase 5** (privacy/legal) now,
   in parallel. **No audit log means you can't prove it wasn't accessed**, which is why audit
   logging is the top gap in the threat model.

## Phase 4: Eradicate

1. Remove the secret from the current code and replace it with a reference to the secret store.
2. **Purge it from git history** (`git filter-repo` or BFG), force-push, and ask GitHub Support
   to clear cached views if needed. This is **hygiene, not the fix**: forks, clones and caches
   may already hold it. That's why rotation comes first.
3. Close the secret-scanning alert as **revoked**.
4. Check for **other copies**: CI logs, PR comments, wiki pages, chat messages, `.env` files.

## Phase 5: Notify (if ePHI may have been exposed)

1. Engage **privacy and legal** immediately.
2. They run the **HIPAA breach risk assessment** (HITECH): nature of the PHI, who accessed it,
   whether it was actually acquired or viewed, and how far the risk has been mitigated.
3. If it's a reportable breach: notify affected individuals **without unreasonable delay and
   no later than 60 days** after discovery; notify HHS (and media for breaches of 500+ residents
   of a state); notify affected practices (covered entities) per the business associate agreement.
4. Security provides the timeline and evidence. Legal owns the notification decision and wording.

## Phase 6: Recover and post-mortem

**Blameless post-mortem within 5 business days.** Answer:
- **Why was it committed?** (No secret store set up? Copy-paste from a tutorial? Unclear guidance?)
- **Why wasn't it caught?** In Phase 5.4, a human-style password passed push protection,
  GitHub secret scanning, default Gitleaks and Semgrep.
- **What changes prevent recurrence?**

**Prevention actions** (examples from this project):
- Custom detection rule for the missed pattern (the `.gitleaks.toml` rule added after 5.4)
- Remove the need for the secret entirely: **managed identity** for Azure resources,
  **OIDC federation** for CI → cloud (no stored cloud credentials in GitHub)
- Keep push protection on; run full-history Gitleaks scans on a schedule
- Developer guidance: User Secrets locally, Key Vault in production, never `appsettings.json`

---

## Scenario B: Compromised third-party GitHub Action

**Real-world precedent:**
- **tj-actions/changed-files (2025):** tags repointed to a commit that dumped CI secrets into build logs
- **aquasecurity/trivy-action (March 2026):** 75+ version tags force-pushed to malicious commits that
  exfiltrated CI secrets before running the real scan (CVE-2026-33634, on CISA KEV)

**Response:**
1. **Identify exposure:** search all workflows for the action
   (`grep -rn "owner/action" .github/workflows/`), and list runs that used it during the
   compromise window (Actions tab / `gh run list`).
2. **Check how it was referenced.** Pinned to a **known-good commit SHA** → that workflow
   was not affected. Referenced by a **tag** (`@v1`) → assume it ran the malicious code.
3. **Rotate every secret those runs could access:** repository and organization secrets,
   cloud credentials, the `GITHUB_TOKEN`'s effective permissions (what could it have written?),
   and any deploy keys.
4. **Review run logs** for the compromise window (secrets dumped to logs, unexpected network
   calls; harden-runner egress logs show outbound connections).
5. **Check for tampering:** unexpected commits, releases, tags, or workflow changes made with the token.
6. **Pin to a verified-safe SHA** (or remove the action), and confirm with `git ls-remote` that the
   SHA is the intended upstream commit.

**Controls already in place in this repo:** every action pinned to a full commit SHA and pinning
**enforced** in repo settings; read-only default token with per-job permissions;
`persist-credentials: false`; harden-runner egress auditing; zizmor on every workflow change;
Dependabot proposing pin updates as reviewable PRs with a 7-day cooldown.

---

## Quick reference

| Step | Do | Don't |
|---|---|---|
| 1 | **Rotate / revoke at the source** | Just delete it in a new commit |
| 2 | Review access logs for the exposure window | Assume nobody saw it |
| 3 | Scope the blast radius; involve privacy/legal if ePHI is possible | Wait for proof of misuse before escalating |
| 4 | Purge history *after* rotation | Treat history rewriting as the fix |
| 5 | Blameless post-mortem + a prevention change | Stop at "be more careful" |
