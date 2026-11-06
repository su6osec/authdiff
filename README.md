# authdiff

[![CI Build & Test](https://github.com/su6osec/authdiff/actions/workflows/ci.yml/badge.svg)](https://github.com/su6osec/authdiff/actions)
[![Release](https://img.shields.io/github/v/release/su6osec/authdiff?color=blue)](https://github.com/su6osec/authdiff/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Montoya API](https://img.shields.io/badge/Montoya%20API-2026.7-blue.svg)](https://portswigger.net/burp/documentation/desktop/extensions)
[![Java 17+](https://img.shields.io/badge/Java-17%2B-orange.svg)](https://adoptium.net/)

> **authdiff** is an automated authorization diffing engine for **Burp Suite Community & Professional** and the **Command Line (CLI)**. It identifies Broken Object Level Authorization (**BOLA** / **IDOR**) and **Missing Authentication** (OWASP Top 10 A01:2021 & OWASP API Security API1:2023) by replaying HTTP traffic captured under a resource owner's session using alternative user identities (a low-privilege attacker and an unauthenticated client) and computing deterministic response differentials.

👉 **[Download Pre-built Burp Extension (`authdiff-burp-all.jar`)](https://github.com/su6osec/authdiff/releases/latest)**

---

## Why authdiff? (Comparison Matrix)

| Capability | authdiff | Legacy Burp Plugins (e.g. Autorize) | Manual Repeater / Diff |
| :--- | :---: | :---: | :---: |
| **Burp Community Compatible** | **Yes** (Montoya API) | Varies (older Extender API) | Yes |
| **Headless / CI CLI Mode** | **Yes** (Offline HAR & Replay) | No (GUI only) | No |
| **Object-ID Awareness** | **Yes** (Path, Query, JSON body) | No (Matches endpoints blindly) | Manual |
| **Dynamic Noise Normalization** | **Yes** (Timestamps, nonces, ETags) | No (Triggers false diffs) | Manual |
| **Linear-Time Comparison** | **Yes** (Token-Set Jaccard $\mathcal{O}(N+M)$) | Levenshtein / raw length | Eye inspection |
| **Deceptive Trap Detection** | **Yes** (200-error, SPA shells, 302 login) | Weak (High false positive rate) | Manual |
| **Safety Defaults** | **Yes** (GET-only default, scope check, rate limit) | User-configured filters | Manual caution |

Available as:
1. **Burp Suite Extension** (Montoya API, fully compatible with **Burp Suite Community Edition**).
2. **Standalone CLI** (for offline HAR evaluation in CI/CD pipelines and headless automated testing).

---

## Legal & Responsible Use Notice

> **IMPORTANT:** `authdiff` is designed strictly for authorized penetration testing, security audits, and security research on applications you own or have explicit, documented permission to test. Replaying requests against unauthorized systems is illegal.

---

## Key Features

- **Object-ID Awareness:** Automatically inspects path segments, query parameters, and JSON request bodies for object identifiers (integers, UUIDs, hex hashes). Findings clearly indicate the targeted resource (e.g. `GET /rest/basket/1: basket=1 accessible by user B`).
- **Deterministic Response Normalization:** Strips dynamic volatile noise before comparison—including timestamps (ISO-8601, UNIX epoch), CSRF nonces, request UUIDs, and volatile headers (`Date`, `ETag`, `X-Request-ID`, `Traceparent`). Canonicalizes JSON key ordering to prevent formatting artifacts.
- **Linear-Time Similarity Metrics:** Uses **Token-Set Jaccard Similarity** ($\mathcal{O}(N+M)$) and JSON structural key-set/value overlap rather than quadratic edit-distance algorithms that choke on large payloads.
- **Trap Resistance:** Specifically flags and handles:
  - **HTTP 200 with logical error bodies** (e.g. `{"error": "Access Denied"}`).
  - **HTTP 302/307 redirects to login endpoints**.
  - **Single Page Application (SPA) HTML shells** served on unauthorized routes.
  - **Public endpoints** via user allowlists and an identical-response suppression heuristic.
- **Strict Safety Defaults:**
  - **Safe Methods Only:** Replays only `GET`, `HEAD`, and `OPTIONS` by default. State-changing verbs (`POST`, `PUT`, `PATCH`, `DELETE`) require an explicit flag or checkbox.
  - **Scope Boundaries:** Refuses requests outside user-specified target hosts.
  - **Rate Limiting:** Defaults to ~2 requests/second with a hard safety cap on total requests.
  - **Credential Redaction:** Redacts `Authorization` headers, cookies, and tokens in all exported logs and reports.

---

## Installation & Build

### Requirements
- **Java 17+** (OpenJDK 17, 21, or newer)
- **Gradle** (or use the included `./gradlew`)

### 1. Build the Project
Clone the repository and build with Gradle:

```bash
git clone https://github.com/su6osec/authdiff.git
cd authdiff
./gradlew build
```

This compiles all modules, runs the test suite, and produces:
- Burp Extension fat JAR: `burp-extension/build/libs/authdiff-burp-all.jar`
- CLI executable: `cli/build/install/cli/bin/cli` (via `./gradlew :cli:installDist`)

---

## Burp Suite Extension Usage

The extension is pinned to **Montoya API 2026.7** and uses **no Pro-only APIs** (no Burp Scanner, no Collaborator). It runs seamlessly in **Burp Suite Community Edition**.

1. In Burp Suite, go to **Extensions** > **Installed** > **Add**.
2. Select **Extension type**: `Java`.
3. Choose the generated fat JAR:
   `burp-extension/build/libs/authdiff-burp-all.jar`
4. Click **Next**. A new Suite Tab named **authdiff** will appear.
5. In the **authdiff** tab:
   - Paste User B's session headers or cookies (e.g. `Cookie: session=attacker_token` or `Authorization: Bearer <TOKEN>`).
   - Configure public path allowlists (e.g. `/api/public/**`) and rate limits.
   - Keep safety defaults enabled (Target Scope Only and Safe Methods Only).
6. In **Proxy HTTP history**, **Repeater**, or **Target**, right-click any request and select:
   **Send to authdiff**
7. View findings in the interactive results table. Click any finding to inspect User A, User B, and Unauthenticated exchanges side-by-side in native Burp message editors.

---

## Standalone CLI Usage

Install the CLI binary locally:
```bash
./gradlew :cli:installDist
```

The CLI executable will be at `./cli/build/install/cli/bin/cli`.

### 1. Offline HAR Comparison (`compare`)
Compare two or three HAR captures recorded under different user sessions without making any network calls:

```bash
./cli/build/install/cli/bin/cli compare \
  --a owner.har \
  --b attacker.har \
  --anon anon.har \
  --format TABLE \
  --fail-on HIGH
```

### 2. Active Replay (`replay`)
Replay captured requests from an owner HAR file with User B's credentials and anonymous mode against an authorized host scope:

```bash
./cli/build/install/cli/bin/cli replay \
  --har owner.har \
  --attacker-header "Authorization: Bearer <USER_B_JWT>" \
  --scope juice.local \
  --format TABLE \
  --out report.json
```

### Real Example Output

```text
================================ authdiff Report ================================
Evaluated 3 request(s) at 2026-11-06T13:39:39.617586Z

METHOD  PATH                             OBJECT-ID        STATUS (A/B/?) SIM (B)    VERDICT                  CONFIDENCE
--------------------------------------------------------------------------------------------------------------------
GET     /rest/basket/1                   basket=1         200 / 200 / 401 100.0%     LIKELY_IDOR_BOLA 100%
GET     /api/Users/1                     Users=1          200 / 200 / 200 100.0%     MISSING_AUTHENTICATION 95%
GET     /api/internal/admin              none             200 / 403 / 401 0.0%       ENFORCED        95%
--------------------------------------------------------------------------------------------------------------------
Summary: Total: 3 | IDOR/BOLA: 1 | Missing Auth: 1 | Enforced: 1 | Inconclusive: 0
Confidence Levels: High: 3 | Medium: 0 | Low: 0
```

---

## Testing & Local Validation

To test `authdiff` against a locally hosted vulnerable target:
1. Start the included **OWASP Juice Shop** container:
   ```bash
   docker compose up -d
   ```
2. Follow the detailed step-by-step walkthrough in [`docs/VALIDATION.md`](docs/VALIDATION.md).

---

## Technical Architecture & Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md): Module diagrams, data flow sequence, and algorithm design rationales.
- [`docs/WALKTHROUGH.md`](docs/WALKTHROUGH.md): File-by-file code explanation and technical interview preparation guide.
- [`docs/FACTS.md`](docs/FACTS.md): Verified test capabilities and factual resume bullets.
- [`docs/NOTES.md`](docs/NOTES.md): Montoya API version pinning notes and observations.
- [`docs/VALIDATION.md`](docs/VALIDATION.md): OWASP Juice Shop validation guide.

---

## Honest Limitations

No automated tool can detect all authorization flaws. Users should understand these architectural boundaries:

1. **Horizontal vs. Vertical Authorization Nuances:** authdiff excels at horizontal authorization checks (replaying User A's object request with User B's token). Vertical authorization (role escalation, e.g. normal user vs admin) is detected when roles yield 403 vs 200, but complex UI-gated multi-tenant permissions may require manual verification.
2. **Multi-Step State Machine Bypasses:** authdiff tests authorization at the HTTP request layer. It does not automatically simulate multi-step workflows (e.g. Step 1: Initialize Draft -> Step 2: Sign -> Step 3: Approve) unless the prerequisite states have already been initialized on the target.
3. **Complex Body Mutation Limitations:** If an endpoint requires swapping User A's ID for User B's in one JSON parameter while retaining User A's ID in another (e.g. `{"recipient": 101, "sender": 202}`), replaying User A's exact request tests whether User B can act on User A's behalf, but does not perform combinatorial field fuzzing.
4. **Heuristics Can Misjudge Unstructured Data:** While JSON payloads are structurally parsed, non-standard APIs returning HTML or plain text with non-standard status codes may be classified as `INCONCLUSIVE`. `authdiff` intentionally prefers `INCONCLUSIVE` over emitting a false positive.

---

## License

Distributed under the [MIT License](LICENSE).
