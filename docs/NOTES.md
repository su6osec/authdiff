# Engineering Notes & Technical Decisions

This file documents key engineering decisions, API observations, and uncertainties encountered during development.

---

## 1. Pinned Montoya API Version

- **Pinned Version:** `net.portswigger.burp.extensions:montoya-api:2026.7`
- **Official Documentation Source:** [PortSwigger Burp Suite Extensions Montoya API](https://portswigger.net/burp/documentation/desktop/extensions) and [Maven Central](https://repo1.maven.org/maven2/net/portswigger/burp/extensions/montoya-api/).
- **Burp Compatibility:** Fully compatible with Burp Suite Community Edition (v2023.12+).
- **Packaging Note:** Montoya API is declared as `compileOnly` in `burp-extension/build.gradle.kts`. When Burp loads an extension, it provides the Montoya runtime implementation classes. Packaging Montoya inside the extension JAR would cause class loader collisions. Conversely, internal dependencies (`core`, Jackson) are bundled into the fat JAR (`authdiff-burp-all.jar`) so Burp can run the extension without requiring external classpath configuration.

---

## 2. API Observations & Implementation Details

### A. ByteArray Object Factory Behavior Outside Burp
- When inspecting `burp.api.montoya.core.ByteArray`, the static factory method `ByteArray.byteArray(String)` delegates to:
  `burp.api.montoya.internal.ObjectFactoryLocator.FACTORY`
- In a standalone JUnit test environment where Burp is not running, `ObjectFactoryLocator.FACTORY` is uninitialized (`null`). Calling `ByteArray.byteArray(...)` directly in unit tests throws a `NullPointerException`.
- **Resolution:** In `MontoyaModelConverterTest`, dynamic interface proxies are used to mock `ByteArray` without invoking the uninitialized static factory or triggering Java 27 ByteBuddy instrumentation issues.

### B. Message Editor Lifecycle in Swing
- Montoya API provides `api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY)` and `createHttpResponseEditor(...)`.
- The returned `HttpRequestEditor` exposes `uiComponent()`, which returns an active Swing `Component` embedding Burp's syntax-highlighted editor.
- When no row is selected or results are cleared, passing `null` to `setRequest(null)` or `setResponse(null)` clears the viewer cleanly without exceptions.

### C. Context Menu Invocations
- In Montoya API, `ContextMenuEvent` can be triggered from multiple UI contexts:
  - `selectedRequestResponses()` is populated when multiple table rows are selected (e.g. in Proxy HTTP history or Target site map).
  - `messageEditorRequestResponse()` is populated when right-clicking directly inside a message viewer in Repeater or Proxy.
- `AuthDiffContextMenuProvider` checks both accessors sequentially to ensure "Send to authdiff" works consistently across all Burp tools.

---

## 3. Uncertainties & Future Improvements

- **Complex Multi-Step Authorization Workflows:**
  - `authdiff` is designed for request-level authorization diffing (replaying individual requests with alternate session credentials). It does not automatically execute pre-requisite multi-step state machines (e.g. initiating a checkout workflow before viewing a receipt).
  - *Mitigation:* The tester captures the exact target endpoint after state initialization under User A, then replays it against User B.
- **Granular Body Mutation for IDOR Testing:**
  - In horizontal authorization flaws where an endpoint takes the owner's ID in a POST body (e.g. `POST /api/transfer {"fromAccount": 101, "toAccount": 202}`), replaying User A's exact body with User B's token tests whether User B can execute operations on User A's account. However, testing whether User B can supply their own account in one field and User A's in another requires semantic body mutation, which is planned for future extension updates.
