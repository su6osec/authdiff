# Codebase Walkthrough & Technical Interview Preparation

This document provides a file-by-file walkthrough of **authdiff** and prepares you for technical interviews. It explains what each class does, why it was implemented that way, and how to defend every architectural choice.

---

## 1. File-by-File Breakdown

### `core` Module (Pure Java 17, Zero Framework Dependencies)

#### Models (`io.github.authdiff.core.model`)
- **`HttpRequest.java` & `HttpResponse.java`:**
  - *What:* Immutable representations of HTTP requests and responses.
  - *Why:* Decouples core logic from Burp's `HttpRequest` or any HTTP client library. Enables offline testing and pure unit testing without mocking heavy external APIs.
- **`ExchangePair.java`:**
  - *What:* Bundles User A's baseline request/response with User B's replayed response and the unauthenticated response.
- **`Verdict.java`:**
  - *What:* Enum defining the four possible classification outcomes: `LIKELY_IDOR_BOLA`, `MISSING_AUTHENTICATION`, `ENFORCED`, and `INCONCLUSIVE`.
  - *Key Detail:* Every finding maps to exactly one verdict.
- **`ConfidenceScore.java`:**
  - *What:* Value object encapsulating a deterministic score (0–100) and categorical band (`HIGH`, `MEDIUM`, `LOW`).
- **`FindingSignal.java`:**
  - *What:* Represents an individual piece of evidence (e.g. status code, object ID detected, similarity metric, trap detected) along with its positive or negative score delta.
- **`IdentifierRef.java`:**
  - *What:* Stores an extracted object identifier (path segment, query param, or JSON field) and its pattern type (`NUMERIC`, `UUID`, `HEX_HASH`).
- **`AuthDiffFinding.java` & `DiffReport.java`:**
  - *What:* Aggregated findings container, summary statistics, and serialization model.

#### Normalization (`io.github.authdiff.core.normalize`)
- **`ResponseNormalizer.java`:**
  - *What:* Cleans dynamic, volatile noise before comparing responses. Strips non-deterministic headers (`Date`, `ETag`, `X-Request-ID`, `Traceparent`), replaces timestamps and CSRF nonces with static tokens (`<TIMESTAMP>`, `<VOLATILE>`), collapses irregular whitespace, and canonicalizes JSON key ordering.
  - *Why:* Prevents dynamic server tokens from skewing similarity calculations.

#### Similarity Algorithms (`io.github.authdiff.core.similarity`)
- **`TokenSetJaccardSimilarity.java`:**
  - *What:* Computes the Jaccard similarity index of token sets: $J(A, B) = \frac{|A \cap B|}{|A \cup B|}$.
  - *Why:* Runs in linear time $\mathcal{O}(N + M)$, bounds output between `[0.0, 1.0]`, and is invariant to harmless token reordering.
- **`JsonStructuralComparator.java`:**
  - *What:* Recursively flattens JSON trees into key-path/value maps. Evaluates key-set schema overlap and shared-value overlap independently.
- **`BodyLengthRatio.java`:**
  - *What:* Computes $\frac{\min(len_1, len_2)}{\max(len_1, len_2)}$. Useful signal for detecting truncated or divergent error pages.

#### Detection & Classification (`io.github.authdiff.core.detection`)
- **`IdentifierDetector.java`:**
  - *What:* Inspects URI path segments, query parameters, and JSON request bodies for object IDs (integers, UUIDs, hex hashes).
- **`TrapDetector.java`:**
  - *What:* Detects deceptive server responses:
    1. HTTP 200 with error/unauthorized JSON payloads.
    2. HTTP 302/307 redirects to login/authentication endpoints.
    3. Generic Single Page Application (SPA) HTML shells.
- **`PathGlobMatcher.java`:**
  - *What:* Fast path-glob matcher for user-defined public endpoint allowlists (e.g. `/api/public/**`, `GET /health`).
- **`AuthDiffClassifier.java`:**
  - *What:* The central decision engine. Normalizes responses, tests for traps and allowlists, evaluates similarity, and emits an `AuthDiffFinding` with explicit, explainable signals.

#### Redaction & Formatting (`io.github.authdiff.core.redact` / `io.github.authdiff.core.format`)
- **`CredentialRedactor.java`:**
  - *What:* Redacts `Authorization`, `Cookie`, `Set-Cookie`, and API keys in requests, responses, and exported reports.
- **`TableFormatter.java`, `JsonReportFormatter.java`, `MarkdownReportFormatter.java`:**
  - *What:* Shared formatting utilities used by both CLI and Burp extension.

---

### `cli` Module (Standalone Testing & Automation)

- **`HarParser.java`:** Parses standard HTTP Archive (HAR 1.2) files into core requests and responses.
- **`HarMatcher.java`:** Matches requests across User A, User B, and Anon captures by method and URI path.
- **`HttpReplayer.java`:** Active replay client built using Java 11+ `java.net.http.HttpClient`. Enforces rate-limiting, scope checking, and method safety defaults.
- **`CompareCommand.java`:** Implements `authdiff compare` for offline evaluation without network access.
- **`ReplayCommand.java`:** Implements `authdiff replay` for active network replay.
- **`AuthDiffCli.java`:** Picocli entrypoint with banner and command dispatch.

---

### `burp-extension` Module (Montoya API, Community Edition)

- **`AuthDiffExtension.java`:** Entrypoint implementing `burp.api.montoya.BurpExtension`. Registers the suite tab, context menu items, and clean shutdown hooks.
- **`AuthDiffWorkerPool.java`:** Manages an asynchronous background thread pool. Ensures HTTP replays never block the Burp UI / Swing Event Dispatch Thread (EDT).
- **`AuthDiffTab.java`:** Swing UI providing configuration inputs, interactive results table, and native Burp message editors for side-by-side comparison.
- **`AuthDiffContextMenuProvider.java`:** Adds "Send to authdiff" right-click action in Proxy history, Repeater, and Target.
- **`MontoyaModelConverter.java`:** Converts between Montoya API types and core authdiff models.
- **`VerdictCellRenderer.java`:** Custom table renderer providing color-coded visual cues for findings.

---

## 2. Technical Interview Questions & Answers

### Q1: Why did you split the project into `core`, `cli`, and `burp-extension`?
> **Answer:** "Separation of concerns. Testing authorization logic inside Burp Suite requires a full desktop environment and GUI interaction, making automated testing and CI difficult. By isolating the data models, normalization algorithms, and classification engine into a pure Java `core` module with zero Burp dependencies, I can unit test every edge case in milliseconds with JUnit 5. The CLI reuses this exact same engine for automated pipelines and offline HAR analysis, while the Burp extension simply provides the GUI adapter."

### Q2: How does authdiff differentiate between an IDOR and a legitimate public endpoint?
> **Answer:** "Public endpoints often return identical data to every user, which naive diffing tools falsely flag as IDOR. authdiff solves this with three layers:
> 1. **User Allowlist:** Testers can define path globs (e.g. `/api/public/**`) that are automatically treated as enforced/exempt.
> 2. **Object-ID Awareness:** authdiff specifically inspects the path, query parameters, and JSON body for numeric IDs, UUIDs, or hashes. If a resource has an explicit object identifier (like `/rest/basket/1`), User B accessing User A's object is a true BOLA/IDOR.
> 3. **Identical Response Heuristic:** If User A, User B, and an unauthenticated client all receive identical content on an endpoint that lacks an object ID (such as `/terms-of-service`), authdiff penalizes confidence and classifies it as `INCONCLUSIVE` rather than producing a false positive."

### Q3: Why did you choose Token-Set Jaccard similarity over Levenshtein edit distance?
> **Answer:** "Levenshtein edit distance has quadratic time and space complexity: $\mathcal{O}(N \times M)$. When analyzing web responses that may reach hundreds of kilobytes, edit distance can lock up threads or trigger `OutOfMemoryError`s. In contrast, Token-Set Jaccard similarity executes in linear time $\mathcal{O}(N + M)$ using hash sets. Furthermore, Levenshtein distance heavily penalizes harmless key reordering in JSON objects, whereas token sets are naturally order-invariant. For JSON payloads, I also supplement Jaccard with a structural comparator that independently checks schema key-set overlap and shared-value overlap."

### Q4: How do you handle false positives caused by Single Page Applications (SPAs)?
> **Answer:** "In SPAs, client-side routing means the server returns the identical `index.html` file (e.g. `<div id='root'></div>` plus bundle scripts) for virtually any route, including unauthorized routes. If an unauthenticated or secondary user requests `/settings` and receives the generic HTML shell, a naive tool might think they accessed the owner's settings. authdiff's `TrapDetector` identifies SPA markers (such as root mount elements and bundle script tags) and flags the result as `INCONCLUSIVE`, preventing false positive IDOR alerts."

### Q5: How did you ensure this extension works in Burp Suite Community Edition?
> **Answer:** "I strictly avoided any Burp Professional-only APIs, such as the active scanner (`montoyaApi.scanner()`) or Collaborator (`montoyaApi.collaborator()`). All functionality is built on core Montoya HTTP and UI APIs (`montoyaApi.http()`, `montoyaApi.userInterface()`, `montoyaApi.scope()`), which are 100% available and fully supported in Burp Community Edition."

### Q6: What thread-safety considerations did you implement in the Burp extension?
> **Answer:** "Any networking or HTTP replay work executed on the Swing Event Dispatch Thread (EDT) will immediately freeze the Burp user interface. To prevent this, `AuthDiffWorkerPool` maintains a dedicated background executor thread. When replays and classification finish, updates to the `JTable` are dispatched back to the EDT using `SwingUtilities.invokeLater(...)`. Additionally, I registered an `ExtensionUnloadingHandler` that calls `shutdownNow()` on the executor service when the extension is unloaded, preventing orphan threads and memory leaks."
