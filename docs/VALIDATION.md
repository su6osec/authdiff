# Local Validation Guide: Testing authdiff Against OWASP Juice Shop

This guide provides step-by-step instructions to validate **authdiff** against a local instance of [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/), an intentionally vulnerable web application containing well-documented Broken Object Level Authorization (BOLA / IDOR) flaws.

---

## 1. Prerequisites

- **Docker & Docker Compose** (to run Juice Shop)
- **Java 17+**
- **Gradle** (or use the included `./gradlew`)
- **Burp Suite Community Edition** (v2023.12+ recommended, supporting Montoya API)

---

## 2. Start the Target Application

From the root of this repository, start OWASP Juice Shop:

```bash
docker compose up -d
```

Verify that Juice Shop is accessible in your browser at:
`http://localhost:3000`

---

## 3. Register Test Accounts

To test authorization differentiation, you need two distinct user identities:

1. Open `http://localhost:3000/#/register` in your browser.
2. **Register User A (Owner):**
   - Email: `owner@juice-sh.op`
   - Password: `Password123!`
   - Security Question: Mother's maiden name (`Smith`)
3. Log in as **User A**, add any product (e.g. *Apple Juice*) to your basket, and log out.
4. **Register User B (Attacker / Secondary User):**
   - Email: `attacker@juice-sh.op`
   - Password: `Password123!`
   - Security Question: Mother's maiden name (`Jones`)
5. Log in as **User B** to verify account creation, but leave User B's basket empty.

---

## 4. Method A: Validation via Burp Suite Extension

### Build the Extension JAR
```bash
./gradlew :burp-extension:build
```
The packaged fat JAR is generated at:
`burp-extension/build/libs/authdiff-burp-all.jar`

### Load into Burp Suite Community Edition
1. Open Burp Suite Community Edition.
2. Navigate to **Extensions** > **Installed** > **Add**.
3. Set **Extension type** to `Java`.
4. Select `burp-extension/build/libs/authdiff-burp-all.jar` and click **Next**.
5. Check the **Output** tab in Burp. You should see:
   ```text
   ======================================================================
      authdiff - Broken Access Control & IDOR/BOLA Detection Extension
   ======================================================================
   Pinned Montoya API: 2026.7
   [authdiff] Extension initialized successfully in Suite tab 'authdiff'.
   ```
6. A new suite tab named **authdiff** will appear in Burp.

### Configure and Run
1. In Burp's Proxy or Browser, log in as **User B** and extract the `Authorization: Bearer <TOKEN>` or `token` cookie.
2. In the **authdiff** tab, paste User B's credentials into the **User B (Attacker) Headers / Cookies** text area:
   ```http
   Authorization: Bearer eyJhbGciOi...
   ```
3. Ensure **Restrict to Target Scope only** is checked, and add `http://localhost:3000` to Burp's Target Scope (**Target** > **Scope**).
4. In your browser (configured with Burp proxy), log back in as **User A** and navigate to your basket (`http://localhost:3000/#/basket`).
5. In Burp's **Proxy** > **HTTP History**, locate the request:
   `GET /rest/basket/1` (or your basket ID)
6. Right-click the request and choose **Send to authdiff**.
7. Return to the **authdiff** tab.

### Expected Behavior
- **Target Endpoint:** `GET /rest/basket/1`
- **Owner (User A):** Returns HTTP 200 with basket items.
- **Attacker (User B):** Juice Shop validates that User B has a valid JWT, but fails to check whether User B owns basket `1`. It returns HTTP 200 with User A's basket data.
- **Anonymous:** Returns HTTP 401 Unauthorized.
- **Verdict:** `LIKELY_IDOR_BOLA` (Confidence: 95–100%)
- **Object ID identified:** `basket=1`

### Your Actual Results (Fill in after running)
```text
<!-- PASTE YOUR BURP EXTENSION TABLE ROW OR SCREENSHOT LOG HERE -->
Index: 
Method: 
URL: 
Status (A / B / Anon): 
Similarity (B): 
Verdict: 
Confidence: 
Notes / Observations:
```

---

## 5. Method B: Validation via Standalone CLI

### Step 1: Capture Traffic to HAR
1. In Chrome / Firefox DevTools (or by selecting requests in Burp and choosing *Copy as HAR* / exporting HAR):
   - Capture User A visiting the basket: save as `owner.har`
   - Capture User B visiting their own basket: save as `attacker.har`
   - Capture an unauthenticated request to the basket endpoint: save as `anon.har`

### Step 2: Run Offline Comparison (No Network)
```bash
./cli/build/install/cli/bin/cli compare \
  --a owner.har \
  --b attacker.har \
  --anon anon.har \
  --format TABLE
```

### Step 3: Run Active Replay
Replay User A's baseline requests using User B's authorization token:

```bash
./cli/build/install/cli/bin/cli replay \
  --har owner.har \
  --attacker-header "Authorization: Bearer <USER_B_JWT_TOKEN>" \
  --scope localhost \
  --format TABLE \
  --out juice-shop-report.json
```

### Expected Output
The CLI prints a colorized summary table:
```text
================================ authdiff Report ================================
Evaluated 1 request(s) at 2026-11-06T14:00:00Z

METHOD  PATH                             OBJECT-ID        STATUS (A/B/?) SIM (B)    VERDICT                  CONFIDENCE
--------------------------------------------------------------------------------------------------------------------
GET     /rest/basket/1                   basket=1         200 / 200 / 401 98.4%      LIKELY_IDOR_BOLA         95%
--------------------------------------------------------------------------------------------------------------------
Summary: Total: 1 | IDOR/BOLA: 1 | Missing Auth: 0 | Enforced: 0 | Inconclusive: 0
Confidence Levels: High: 1 | Medium: 0 | Low: 0
```

### Your Actual Results (Fill in after running)
```text
<!-- PASTE YOUR CLI OUTPUT TABLE HERE -->
Command executed:
Exit code:
Terminal output:
```

---

## 6. Teardown

Stop the local container once testing is complete:
```bash
docker compose down
```
