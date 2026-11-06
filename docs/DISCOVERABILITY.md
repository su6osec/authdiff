# Online Discoverability, Community Outreach & SEO Guide

This guide details exact, high-leverage steps to make **authdiff** discoverable across search engines, GitHub, and the wider Application Security / Bug Bounty community.

---

## 1. What Has Been Completed Automatically

- [x] **20 High-Intent GitHub Topics Added:** Configured tags including `idor`, `bola`, `broken-access-control`, `burp-suite`, `burp-extension`, `montoya-api`, `appsec`, `penetration-testing`, `security-tools`, `api-security`, `bug-bounty`, and `owasp-top-10`.
- [x] **SEO-Optimized Repository Description & Homepage:** Pinned descriptive summary referencing OWASP A01 and Burp Suite Community.
- [x] **Pre-built GitHub Release (`v0.1.0`):** Packaged `authdiff-burp-all.jar` attached as a downloadable binary. (Google Search indexes GitHub releases with attached assets higher in technical search rankings).
- [x] **Feature Comparison Matrix in README:** Structured markdown table targeting search queries like *"Autorize vs authdiff"* and *"Burp Suite Community IDOR extension"*.

---

## 2. High-Impact GitHub Awesome Lists to Submit

GitHub "Awesome" lists rank at the top of Google results for security tooling. Submitting a Pull Request to these lists provides immediate backlinks and developer traffic:

1. **`awesome-burp-extensions`**
   - Repository: [snoopysecurity/awesome-burp-extensions](https://github.com/snoopysecurity/awesome-burp-extensions)
   - Category: *Access Control / Authorization*
   - Description to submit: `[authdiff](https://github.com/su6osec/authdiff) - Modern Montoya API extension and CLI for detecting IDOR/BOLA and missing auth with deterministic diffing.`
2. **`awesome-appsec`**
   - Repository: [paragonie/awesome-appsec](https://github.com/paragonie/awesome-appsec)
   - Category: *Vulnerability Scanners & Auditing Tools*
3. **`awesome-bugbounty-tools`**
   - Repository: [vavkamil/awesome-bugbounty-tools](https://github.com/vavkamil/awesome-bugbounty-tools)
   - Category: *Burp Suite Plugins / API Security*
4. **`awesome-security`**
   - Repository: [sbilly/awesome-security](https://github.com/sbilly/awesome-security)

---

## 3. Submit to PortSwigger BApp Store

The PortSwigger BApp Store is built into every Burp Suite installation globally:

1. Review the [BApp Store submission guidelines](https://portswigger.net/burp/documentation/desktop/extensions/submitting-bapps).
2. Fork the [PortSwigger/bapp-manifests](https://github.com/PortSwigger/bapp-manifests) repository.
3. Submit a Pull Request with an `authdiff.bapp` manifest pointing to `su6osec/authdiff`.
4. *Key Advantage:* `authdiff` already adheres strictly to all BApp guidelines:
   - Uses the latest Montoya API (`2026.7`).
   - Runs cleanly in Burp Suite Community Edition.
   - Zero Pro-only dependencies.
   - Non-blocking execution off the UI thread.

---

## 4. Community Announcement Templates

When sharing on forums, lead with technical problems solved (e.g. *how it handles SPA shells and dynamic timestamps without false positives*):

### Reddit (`r/netsec`, `r/bugbounty`, `r/websecurity`)
**Title:**
> *authdiff: An open-source IDOR / BOLA diffing engine for Burp Suite Community (Montoya API) and CLI*

**Post Body:**
```text
Hey everyone,

I built authdiff, an open-source authorization diffing tool designed to test for IDOR/BOLA and missing authentication flaws across multi-user sessions.

Why I built it:
Existing diffing extensions often flood users with false positives caused by:
1. Volatile server data (timestamps, CSRF tokens, request UUIDs, ETags)
2. SPA HTML shells returning identical content for all client routes
3. HTTP 200 responses containing logical error bodies

How authdiff handles this:
- Normalizes responses by stripping dynamic noise before diffing.
- Uses linear-time Token-Set Jaccard similarity and JSON structural key-set diffing (no O(N*M) edit-distance lockups).
- Works 100% in Burp Suite Community Edition via the new Montoya API (no Pro-only APIs used).
- Ships with a standalone CLI for offline HAR diffing in CI/CD pipelines.
- Built-in safety guards: replays safe methods (GET/HEAD/OPTIONS) by default, strictly validates scope, and rate-limits requests.

Code, pre-built JARs, and architecture docs:
https://github.com/su6osec/authdiff

Feedback, issues, and PRs are welcome!
```

---

## 5. Write a Technical Blog Post

Publishing a walkthrough on Medium, Dev.to, or your personal blog creates permanent SEO equity:
- **Title Idea:** *"Hunting IDORs and BOLA at Scale: Why We Built authdiff for Burp Community & CLI"*
- Include:
  - Step-by-step example using OWASP Juice Shop (from [`docs/VALIDATION.md`](VALIDATION.md)).
  - Screenshots of the Burp Suite side-by-side message editor.
  - Backlinks to `https://github.com/su6osec/authdiff`.
