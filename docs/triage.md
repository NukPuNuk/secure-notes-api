# Triage: Intentionally Vulnerable PR

Triage records for the four bugs deliberately introduced in
[PR #1: DEMO: intentionally vulnerable changes](https://github.com/NukPuNuk/secure-notes-api/pull/1),
plus one issue found on `main` during testing. **All data is synthetic. No real PHI.**

**How severity is rated:** the scanner's severity is the *starting point*, not the verdict.
Each finding is re-rated for **this** application: a multi-tenant API that stores
therapy notes (ePHI) for many independent practices. The questions are: who can exploit
it, what they get, and whether it crosses a tenant boundary.

## Summary

| ID | Finding | Detected by | Tool severity | **Contextual severity** | Verdict |
|---|---|---|---|---|---|
| F-1 | IDOR / broken object-level authorization | **Manual test only** | n/a (no tool fired) | **Critical** | True positive |
| F-2 | SQL injection in note search | CodeQL `cs/sql-injection`, compiler EF1002 | High | **Critical** | True positive |
| F-3 | Vulnerable dependency: Newtonsoft.Json 12.0.1 | dependency-review, NuGet audit | High | **Low** | True positive |
| F-4 | Hardcoded database admin password | **Custom Gitleaks rule only** | n/a (defaults missed it) | **Critical** *(if real)* | True positive |
| F-5 | Missing-claim crash and verbose error output | Manual test | n/a | **Low** | True positive |

---

## F-1: IDOR (Broken Object-Level Authorization)

- **Source:** Manual cross-tenant test. **Missed by every automated tool:** CodeQL
  (`security-extended`), Semgrep (`p/csharp`), and all other CI checks passed.
- **Location:** `src/NotesApi/Controllers/NotesController.cs`, `Get(int id)`, commit `84879f7`
- **Change:** `SingleOrDefaultAsync(n => n.Id == id && n.PracticeId == PracticeId)` was replaced
  with `FindAsync(id)`. The tenant filter is gone. The comment above it still claims
  object-level authorization.
- **Verdict:** True positive
- **Severity (in context): Critical**
  - Any authenticated user at **any** practice can read **any** practice's notes.
  - The exploit is trivial (change one number in the URL), and note IDs are sequential, so the
    **entire dataset can be enumerated**.
  - It crosses the tenant boundary, the most important isolation guarantee in a multi-tenant
    EHR. In production this would be a reportable HIPAA breach affecting every customer.
  - OWASP API Security Top 10 **API1: Broken Object Level Authorization**.
- **Evidence:** the branch code was run locally with dev JWTs for practice 1 and practice 2.

  | Request | `main` | PR branch |
  |---|---|---|
  | Practice 1 token → `GET /notes/3` (practice 2's note) | 404 | **200**, "Test Patient C" |
  | Practice 2 token → `GET /notes/1` (practice 1's note) | 404 | **200**, "Test Patient A" |
  | No token → `GET /notes/3` | 401 | 401 |

  Authentication still worked (401 without a token). Only authorization was missing.
- **Why tools missed it:** SAST looks for untrusted data reaching a dangerous function.
  Passing `id` to `FindAsync` is normal. The bug is a *missing* business rule ("every query
  filters by tenant") that only this application knows about.
- **Fix:** keep the ownership check in the query, as on
  [`main`, line 18](https://github.com/NukPuNuk/secure-notes-api/blob/46dd84c/src/NotesApi/Controllers/NotesController.cs#L18).
  Cross-tenant requests return **404, not 403**, so the API doesn't reveal that the record exists.
- **Prevention:**
  - Automated tests that assert cross-tenant access fails (practice 1 → practice 2 record = 404).
  - A custom Semgrep rule flagging any `db.Notes` query without a `PracticeId` filter.
  - Centralized tenant filtering, e.g. an EF Core **global query filter** on `PracticeId`, so
    developers can't forget it.
  - Authorization-focused code review, and threat modeling (STRIDE: Information Disclosure).

---

## F-2: SQL Injection in Note Search

- **Source:** **CodeQL alert #25, `cs/sql-injection`** (PR check failed). Also the C# compiler
  warning **EF1002** ("FromSqlRaw inserts interpolated strings directly into the SQL"). **Missed by:** Semgrep.
- **Location:** `src/NotesApi/Controllers/NotesController.cs:26`, `Search(string patient)`, commit `f0064ec`
- **Change:** parameterized LINQ (`Where(... Contains(patient))`) was replaced with
  `FromSqlRaw($"... PatientName LIKE '%{patient}%'")`. C# string interpolation pastes user
  input into the SQL text before it reaches the database.
- **Verdict:** True positive
- **Severity (in context): Critical** *(CodeQL: High)*
  - **Raised from High** because in this app the injection **bypasses tenant isolation**. The
    query still contains `PracticeId = 1`, but the payload rewrites the `WHERE` clause.
  - A UNION payload read the database's own schema table, so reads aren't limited to the Notes table.
  - It's reachable by any authenticated user, through a normal search box.
- **Evidence (branch code, practice 1 token):**

  | `?patient=` | Result |
  |---|---|
  | `Test` | 200: Patients A and B (practice 1 only, as expected) |
  | `'` | **500 with a raw `SqliteException` and stack trace**, confirming injection |
  | `%' OR 1=1 --` | **200: A, B and Test Patient C (practice 2)**. Tenant filter bypassed |
  | `x' UNION SELECT … FROM sqlite_master --` | **200: rows from the schema table** |

- **Fix:** use parameterized queries, as on
  [`main`, line 25](https://github.com/NukPuNuk/secure-notes-api/blob/46dd84c/src/NotesApi/Controllers/NotesController.cs#L25)
  (LINQ). If raw SQL is truly needed, use `FromSql($"...")`, which converts interpolated
  values into parameters. **Never** use `FromSqlRaw` with interpolation or concatenation.
- **Prevention:**
  - CodeQL on every PR (already in place; it blocked this one).
  - Add a CI build step with `-warnaserror:EF1002` so the compiler's own warning becomes a gate.
  - Least-privilege database account (read/write on app tables only) to limit what injection can reach.
  - Generic error responses in production (see F-5), so attackers don't get SQL error details.

---

## F-3: Vulnerable Dependency (Newtonsoft.Json 12.0.1)

- **Source:** **dependency-review** (PR check failed; posted a summary comment) and the
  **nuget-audit** job (failed). NuGet also warned **NU1903** locally on restore.
- **Location:** `src/NotesApi/NotesApi.csproj`, commit `fc9098e`
- **Advisory:** [GHSA-5crp-9r3c-p9vr](https://github.com/advisories/GHSA-5crp-9r3c-p9vr):
  Improper Handling of Exceptional Conditions. Deeply nested JSON can cause a **denial of
  service** (stack or CPU exhaustion). Fixed in **13.0.1**.
- **Verdict:** True positive (the vulnerable version is really present)
- **Severity (in context): Low** *(tools: High)*
  - **Lowered from High** because the vulnerable code isn't **reachable**. The API uses
    ASP.NET Core's built-in `System.Text.Json`, and nothing calls Newtonsoft.
  - The impact class is availability (DoS), not confidentiality. No PHI exposure.
  - **It's still fixed, not accepted.** The package ships with the app, a future developer could
    start using it, and reachability can change without anyone noticing.
- **Fix:** remove the unused package. If it's ever needed, require `>= 13.0.1`.
  `main` has no Newtonsoft reference.
- **Prevention:**
  - dependency-review with `fail-on-severity: high` blocks new vulnerable packages before merge (already in place).
  - Dependabot security updates for anything already on `main` (enabled).
  - Dependabot `cooldown` (7 days) to avoid adopting freshly compromised releases.
  - Periodically remove unused dependencies to shrink the attack surface.

---

## F-4: Hardcoded Database Admin Password

- **Source:** **custom Gitleaks rule `connection-string-password`** (added in `c86ed51`;
  PR check then failed).
  **Missed by all default layers:** GitHub push protection, GitHub secret scanning, Gitleaks'
  built-in rules and Semgrep `p/secrets`. GitHub's "non-provider patterns" detection isn't
  available on this free personal repo.
- **Location:** `src/NotesApi/appsettings.json:11`, commit `aac24e7`
- **Change:** added a `Reporting` connection string containing `User Id=sa;Password=…`.
  The value is fake and the host (`reports.example.internal`) is non-routable.
- **Verdict:** True positive. It's a credential pattern in source control, regardless of whether
  this particular value works.
- **Severity (in context): Critical if real**
  - `sa` is SQL Server's built-in **administrator**: full read, write and delete on every
    database on that server, which would include PHI.
  - The repo is **public**. Bots scrape new commits for credentials within minutes.
  - Removing it in a later commit doesn't help, because it stays in git history.
- **Evidence:** the Gitleaks job failed with `RuleID: connection-string-password`,
  `File: src/NotesApi/appsettings.json`, `Line: 11`, `Commit: aac24e7`. The secret was
  `REDACTED` in the CI logs.
- **Response (if this were a real credential):**
  1. **Rotate the password immediately.** That's the only real fix once a secret is public.
  2. Review database and server logs for use since the commit time.
  3. Scope the blast radius: what could `sa` reach? Was any PHI accessed? → privacy/legal (HITECH breach assessment).
  4. Purge from history (e.g. `git filter-repo`) *after* rotation, as hygiene rather than as the fix.
  5. Post-mortem: why did it get committed, and why didn't detection catch it?
- **Fix:** no credentials in config files. `main`'s
  [`appsettings.json`](https://github.com/NukPuNuk/secure-notes-api/blob/46dd84c/src/NotesApi/appsettings.json)
  contains only a credential-free SQLite path.
  - Local development: **User Secrets** (`dotnet user-secrets`), stored outside the repo.
  - Production: **Azure Key Vault**, or better, **managed identity**, so no password exists at all.
- **Prevention:**
  - Keep the custom Gitleaks rule (`.gitleaks.toml`) and merge it to `main`.
  - Push protection for provider tokens (enabled).
  - Never use admin accounts for applications. Use a least-privilege database user.
- **Lesson:** detection is incomplete, especially for human-style passwords. Prevention
  (no secrets in code) matters more than any scanner.

---

## F-5: Missing-Claim Crash and Verbose Error Output (found on `main`)

- **Source:** manual testing during Phase 1.7. **Present on `main`.**
- **Location:** `src/NotesApi/Controllers/NotesController.cs:12`:
  `int.Parse(User.FindFirst("practice_id")!.Value)`
- **Behaviour:** a validly signed token **without** a `practice_id` claim causes an unhandled
  exception → **HTTP 500**. In the Development environment, the response body includes the
  full stack trace. The same verbose output appeared during the F-2 SQL injection probe
  (raw `SqliteException`).
- **Verdict:** True positive
- **Severity (in context): Low**
  - It **fails closed**: no data is returned.
  - ASP.NET Core shows the Developer Exception Page **only in Development**. In Production it
    would be a bare 500, so the information disclosure is limited to misconfigured deployments
    (OWASP A05: Security Misconfiguration).
  - It's still a robustness bug: a missing claim should be a clear authorization failure, not a crash.
- **Fix (not yet applied):**
  - Validate the claim and return **403 Forbidden** when it's missing or not a number
    (`int.TryParse`), or enforce it with an authorization policy (`RequireClaim("practice_id")`).
  - Add `app.UseExceptionHandler()` plus ProblemDetails for non-Development environments.

---

## Other Triage Decisions (non-bugs and pipeline findings)

| Observation | Decision | Reasoning |
|---|---|---|
| Dependabot `github_actions` job failed: "no workflow files found" | **Expected; no action** | No workflows existed yet. It resolved once workflows were added. |
| `codeql-action` pin appeared not to match its tag | **Not a hijack; pin is correct** | Annotated tags have two SHAs (tag object vs. commit `^{}`). The pinned commit is the dereferenced, GitHub-verified commit. |
| Gitleaks reported "no leaks" after scanning **1 commit** | **Coverage gap; fixed** | Push events scan only new commits. Added `workflow_dispatch` for full-history scans (8/8 commits). |
| zizmor: 14 × `unpinned-uses` + 1 × `unpinned-images` | **True positives; fixed** | Pinned all actions to commit SHAs (pinact) and the Semgrep image to a digest. Repo now enforces SHA pinning. |
| Semgrep missed F-2 (SQLi) | **Accepted tool limitation** | Generic rules didn't model EF Core's `FromSqlRaw`. CodeQL caught it, which is why the pipeline runs two SAST engines. |

## Scorecard

| Bug | Default automation | With custom rule | Human |
|---|---|---|---|
| F-1 IDOR | ❌ | ❌ (custom Semgrep rule planned) | ✅ |
| F-2 SQLi | ✅ CodeQL | ✅ | ✅ |
| F-3 Vulnerable dependency | ✅ dependency-review, NuGet audit | ✅ | ✅ |
| F-4 Hardcoded secret | ❌ | ✅ custom Gitleaks rule | ✅ |

**Default tools caught 2 of 4; tuned tools caught 3 of 4.** The misses were business logic
(authorization) and context (is this string a credential?). Scanners are a floor, not a
ceiling: they need threat modeling, authorization-focused review and targeted tests alongside them.
