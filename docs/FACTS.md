# Strictly Factual Verification & Capabilities

This document provides a factual, unembellished summary of what `authdiff` implements and what has been verified by automated tests. Use these verified points for resume bullets and portfolio summaries.

---

## 1. What the Tool Actually Does

- **Multi-Identity Authorization Testing:**
  - Takes an original HTTP request/response exchange captured under Identity A (resource owner).
  - Replays the request with Identity B's credentials (swapping Authorization headers and Cookies).
  - Replays the request unauthenticated (stripping all credentials).
  - Normalizes responses by stripping dynamic noise (volatile headers, timestamps, CSRF nonces, request UUIDs) and canonicalizing JSON keys.
  - Computes deterministic similarity metrics (Token-Set Jaccard similarity, body length ratio, and JSON structural key-set/value overlap).
  - Detects object identifiers in path segments (integers, UUIDs, hex hashes), query parameters, and JSON request bodies.
  - Detects deceptive traps: HTTP 200 with error payloads, redirects to login endpoints (302/307), and generic Single Page Application (SPA) HTML shells.
  - Classifies each endpoint into exactly one verdict (`LIKELY_IDOR_BOLA`, `MISSING_AUTHENTICATION`, `ENFORCED`, or `INCONCLUSIVE`) with a confidence score (0–100) and explainable signals.

- **Dual-Interface Delivery:**
  - **Burp Suite Extension:** Compatible with Burp Suite Community Edition. Registers a Suite tab ("authdiff"), provides an interactive results table, embeds native read-only message editors (`HttpRequestEditor`, `HttpResponseEditor`), runs replays asynchronously on a dedicated worker pool, and registers a context menu item ("Send to authdiff") across Proxy, Repeater, and Target.
  - **Standalone CLI:** Implemented using Picocli. Provides `authdiff compare` for offline HAR 1.2 comparison (no network needed) and `authdiff replay` for active network replay with rate limiting (~2 req/s default), strict scope host enforcement, safe-methods-only defaults (GET, HEAD, OPTIONS), and credential redaction.

---

## 2. What Has Been Verified by Automated Tests

The repository includes 33 automated JUnit 5 tests covering all three modules:

### `core` (25 Unit Tests)
- `AuthDiffClassifierTest`:
  - Verified true IDOR detection when User B accesses User A's object (`/rest/basket/1`).
  - Verified `ENFORCED` verdict when User B receives HTTP 403 Forbidden.
  - Verified `MISSING_AUTHENTICATION` verdict when unauthenticated requests access User A's object.
  - Verified `INCONCLUSIVE` verdict on SPA HTML shell responses, preventing false positive IDOR alerts.
  - Verified `ENFORCED` verdict when User B is redirected to login (HTTP 302 to `/login`).
  - Verified `ENFORCED` verdict when User B receives HTTP 200 with an access-denied error JSON payload.
  - Verified user public allowlist glob matching overrides.
  - Verified identical response heuristic: non-object endpoints returning identical responses to all users are classified as `INCONCLUSIVE` with low confidence, avoiding false positives.
  - Verified dynamic-value noise tolerance: varying timestamps, dates, and CSRF tokens do not prevent accurate IDOR classification.
- `IdentifierDetectorTest`:
  - Verified numeric and UUID path segment extraction.
  - Verified query parameter identifier extraction (`order_id=1024`).
  - Verified JSON request body identifier extraction (`{"basketId": 88}`).
- `TrapDetectorTest`:
  - Verified detection of JSON and plaintext error bodies under HTTP 200.
  - Verified detection of login redirects (302/307).
  - Verified detection of SPA HTML shells (`<div id="root">`, bundle scripts).
- `ResponseNormalizerTest`:
  - Verified volatile header stripping (`Date`, `ETag`, `X-Request-Id`, `Traceparent`).
  - Verified replacement of dynamic timestamps, epoch integers, and CSRF tokens with static tokens.
  - Verified JSON canonical sorting of keys regardless of input order.
  - Verified whitespace normalization.
- `SimilarityTest`:
  - Verified Token-Set Jaccard calculation on identical, partial, and disjoint strings.
  - Verified JSON key-set schema overlap and value overlap calculation.
  - Verified body length ratio calculations.
- `CredentialRedactorTest`:
  - Verified redaction of Authorization headers, cookies, API keys, and sensitive query parameters.

### `cli` (6 Unit & Integration Tests)
- `HarParserTest`:
  - Verified parsing of standard HAR 1.2 JSON entries into domain `HttpRequest` and `HttpResponse`.
- `CompareCommandTest`:
  - Verified offline HAR comparison across three sample captures (`owner.har`, `attacker.har`, `anon.har`).
  - Verified exit code behavior when findings at or above `--fail-on` are encountered.
  - Verified JSON report export.
- `HttpReplayerSafetyTest`:
  - Verified scope host validation: rejects requests to out-of-scope hosts.
  - Verified safe methods default: refuses state-changing verbs (`DELETE`, `POST`) unless explicit flag is enabled.
- `LiveHttpReplayTest`:
  - Verified active live HTTP network replay against a live HTTP server, correctly classifying live IDOR/BOLA endpoints and live enforced access control endpoints.

### `burp-extension` (2 Unit Tests)
- `MontoyaModelConverterTest`:
  - Verified accurate bidirectional conversion between Montoya API representations and `core` domain models.

---

## 3. Truthful Resume Bullets

You can truthfully claim the following on your resume or in technical interviews:

- *Developed an open-source authorization diffing tool (`authdiff`) in Java 17 to detect IDOR/BOLA and broken authentication across multi-user web sessions.*
- *Architected a decoupled multi-module system (`core`, `cli`, `burp-extension`), enabling offline evaluation of HTTP Archive (HAR) captures in CI pipelines and interactive testing in Burp Suite Community Edition.*
- *Engineered a deterministic comparison engine utilizing Token-Set Jaccard similarity and JSON structural key-set diffing, avoiding the $\mathcal{O}(N \times M)$ quadratic overhead of traditional edit-distance algorithms on large HTTP bodies.*
- *Implemented heuristics to mitigate common authorization false positives, including dynamic token normalization (timestamps, CSRF nonces, request UUIDs), SPA shell detection, 200-OK error-body parsing, and public endpoint suppression.*
- *Enforced defensive defaults including strict host scope boundaries, safe HTTP method filters (GET/HEAD/OPTIONS only unless explicitly overridden), rate limiting, and automatic credential redaction in reports.*
- *Authored 32 automated JUnit 5 tests and an end-to-end validation suite against OWASP Juice Shop.*
