package io.github.authdiff.core.detection;

import io.github.authdiff.core.model.AuthDiffFinding;
import io.github.authdiff.core.model.ExchangePair;
import io.github.authdiff.core.model.HttpRequest;
import io.github.authdiff.core.model.HttpResponse;
import io.github.authdiff.core.model.Verdict;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class AuthDiffClassifierTest {

    private final AuthDiffClassifier classifier = new AuthDiffClassifier();

    @Test
    @DisplayName("True IDOR / BOLA: Attacker B accesses owner A's object successfully")
    void testTrueIdorBola() {
        HttpRequest ownerReq = HttpRequest.builder()
                .method("GET")
                .url("https://juice.local/rest/basket/1")
                .path("/rest/basket/1")
                .header("Authorization", "Bearer token-owner-user-a")
                .build();

        HttpResponse ownerRes = HttpResponse.builder()
                .statusCode(200)
                .body("{\"status\": \"success\", \"data\": {\"id\": 1, \"UserId\": 1, \"Products\": [{\"id\": 12, \"name\": \"Orange Juice\"}]}}")
                .build();

        // User B sends same request with User B token and gets the same basket data
        HttpResponse attackerRes = HttpResponse.builder()
                .statusCode(200)
                .body("{\"status\": \"success\", \"data\": {\"id\": 1, \"UserId\": 1, \"Products\": [{\"id\": 12, \"name\": \"Orange Juice\"}]}}")
                .build();

        // Anon request gets 401 Unauthorized
        HttpResponse anonRes = HttpResponse.builder()
                .statusCode(401)
                .body("{\"error\": \"Unauthorized\"}")
                .build();

        ExchangePair exchange = new ExchangePair(ownerReq, ownerRes, attackerRes, anonRes);
        AuthDiffFinding finding = classifier.classify(exchange);

        assertThat(finding.verdict()).isEqualTo(Verdict.LIKELY_IDOR_BOLA);
        assertThat(finding.confidence().value()).isGreaterThanOrEqualTo(80);
        assertThat(finding.humanSummary()).contains("/rest/basket/1");
        assertThat(finding.humanSummary()).contains("basket=1");
        assertThat(finding.primaryIdentifierString()).isEqualTo("basket=1");
    }

    @Test
    @DisplayName("Enforced: Attacker receives 403 Forbidden on owner object")
    void testEnforced403() {
        HttpRequest ownerReq = HttpRequest.builder()
                .method("GET")
                .url("https://juice.local/rest/basket/1")
                .path("/rest/basket/1")
                .build();

        HttpResponse ownerRes = HttpResponse.builder()
                .statusCode(200)
                .body("{\"data\": {\"id\": 1, \"items\": []}}")
                .build();

        HttpResponse attackerRes = HttpResponse.builder()
                .statusCode(403)
                .body("{\"error\": \"Forbidden: Not your basket\"}")
                .build();

        HttpResponse anonRes = HttpResponse.builder()
                .statusCode(401)
                .body("{\"error\": \"Unauthorized\"}")
                .build();

        ExchangePair exchange = new ExchangePair(ownerReq, ownerRes, attackerRes, anonRes);
        AuthDiffFinding finding = classifier.classify(exchange);

        assertThat(finding.verdict()).isEqualTo(Verdict.ENFORCED);
        assertThat(finding.confidence().value()).isGreaterThanOrEqualTo(90);
    }

    @Test
    @DisplayName("Missing Authentication: Anonymous client receives success response similar to owner")
    void testMissingAuthentication() {
        HttpRequest ownerReq = HttpRequest.builder()
                .method("GET")
                .url("https://juice.local/api/Users/1")
                .path("/api/Users/1")
                .build();

        HttpResponse ownerRes = HttpResponse.builder()
                .statusCode(200)
                .body("{\"user\": {\"id\": 1, \"email\": \"admin@juice.local\", \"role\": \"admin\"}}")
                .build();

        HttpResponse attackerRes = HttpResponse.builder()
                .statusCode(200)
                .body("{\"user\": {\"id\": 1, \"email\": \"admin@juice.local\", \"role\": \"admin\"}}")
                .build();

        HttpResponse anonRes = HttpResponse.builder()
                .statusCode(200)
                .body("{\"user\": {\"id\": 1, \"email\": \"admin@juice.local\", \"role\": \"admin\"}}")
                .build();

        ExchangePair exchange = new ExchangePair(ownerReq, ownerRes, attackerRes, anonRes);
        AuthDiffFinding finding = classifier.classify(exchange);

        assertThat(finding.verdict()).isEqualTo(Verdict.MISSING_AUTHENTICATION);
        assertThat(finding.confidence().value()).isGreaterThanOrEqualTo(90);
    }

    @Test
    @DisplayName("SPA shell trap: Attacker receives generic SPA HTML, preventing false positive IDOR")
    void testSpaShellTrap() {
        HttpRequest ownerReq = HttpRequest.builder()
                .method("GET")
                .url("https://spa.example.com/app/dashboard/settings")
                .path("/app/dashboard/settings")
                .build();

        HttpResponse ownerRes = HttpResponse.builder()
                .statusCode(200)
                .header("Content-Type", "application/json")
                .body("{\"user\": \"owner\", \"settings\": {\"dark_mode\": true}}")
                .build();

        // Server catches route and serves index.html shell to unauthorized attacker
        HttpResponse attackerRes = HttpResponse.builder()
                .statusCode(200)
                .header("Content-Type", "text/html")
                .body("<!doctype html><html><body><div id=\"root\"></div><script src=\"/bundle.js\"></script></body></html>")
                .build();

        ExchangePair exchange = new ExchangePair(ownerReq, ownerRes, attackerRes, null);
        AuthDiffFinding finding = classifier.classify(exchange);

        assertThat(finding.verdict()).isEqualTo(Verdict.INCONCLUSIVE);
        assertThat(finding.signals()).anyMatch(s -> "SPA_SHELL_DETECTED".equals(s.code()));
    }

    @Test
    @DisplayName("Redirect to login: Attacker receives 302 to /login, correctly classified as ENFORCED")
    void testRedirectToLogin() {
        HttpRequest ownerReq = HttpRequest.builder()
                .method("GET")
                .url("https://app.example.com/invoices/999")
                .path("/invoices/999")
                .build();

        HttpResponse ownerRes = HttpResponse.builder()
                .statusCode(200)
                .body("{\"invoiceId\": 999, \"amount\": 150.0}")
                .build();

        HttpResponse attackerRes = HttpResponse.builder()
                .statusCode(302)
                .header("Location", "/login?returnUrl=/invoices/999")
                .body("")
                .build();

        ExchangePair exchange = new ExchangePair(ownerReq, ownerRes, attackerRes, null);
        AuthDiffFinding finding = classifier.classify(exchange);

        assertThat(finding.verdict()).isEqualTo(Verdict.ENFORCED);
        assertThat(finding.signals()).anyMatch(s -> "ATTACKER_LOGIN_REDIRECT".equals(s.code()));
    }

    @Test
    @DisplayName("200 with error body: Attacker receives 200 OK with error payload, classified as ENFORCED")
    void test200WithLogicalError() {
        HttpRequest ownerReq = HttpRequest.builder()
                .method("GET")
                .url("https://api.example.com/account/456")
                .path("/account/456")
                .build();

        HttpResponse ownerRes = HttpResponse.builder()
                .statusCode(200)
                .body("{\"id\": 456, \"balance\": 999.00}")
                .build();

        HttpResponse attackerRes = HttpResponse.builder()
                .statusCode(200)
                .body("{\"error\": \"Unauthorized: You lack permissions for this account\"}")
                .build();

        ExchangePair exchange = new ExchangePair(ownerReq, ownerRes, attackerRes, null);
        AuthDiffFinding finding = classifier.classify(exchange);

        assertThat(finding.verdict()).isEqualTo(Verdict.ENFORCED);
        assertThat(finding.signals()).anyMatch(s -> "ATTACKER_200_WITH_ERROR_BODY".equals(s.code()));
    }

    @Test
    @DisplayName("User public allowlist: Endpoint matching allowlist glob is marked ENFORCED")
    void testPublicAllowlist() {
        AuthDiffClassifier customClassifier = new AuthDiffClassifier(
                new AuthDiffClassifier.Options(List.of("/api/public/**", "GET /rest/products/search"), 0.70, 0.85)
        );

        HttpRequest ownerReq = HttpRequest.builder()
                .method("GET")
                .url("https://example.com/api/public/version")
                .path("/api/public/version")
                .build();

        HttpResponse ownerRes = HttpResponse.builder().statusCode(200).body("{\"v\": 1}").build();
        HttpResponse attackerRes = HttpResponse.builder().statusCode(200).body("{\"v\": 1}").build();
        HttpResponse anonRes = HttpResponse.builder().statusCode(200).body("{\"v\": 1}").build();

        ExchangePair exchange = new ExchangePair(ownerReq, ownerRes, attackerRes, anonRes);
        AuthDiffFinding finding = customClassifier.classify(exchange);

        assertThat(finding.verdict()).isEqualTo(Verdict.ENFORCED);
        assertThat(finding.confidence().value()).isEqualTo(100);
    }

    @Test
    @DisplayName("Identical response heuristic on non-object endpoints prevents false positive IDOR")
    void testIdenticalPublicEndpointHeuristic() {
        HttpRequest ownerReq = HttpRequest.builder()
                .method("GET")
                .url("https://example.com/terms-and-conditions")
                .path("/terms-and-conditions")
                .build();

        HttpResponse commonRes = HttpResponse.builder()
                .statusCode(200)
                .body("<html><body>Standard Terms and Conditions for all users.</body></html>")
                .build();

        ExchangePair exchange = new ExchangePair(ownerReq, commonRes, commonRes, commonRes);
        AuthDiffFinding finding = classifier.classify(exchange);

        // Not flagged as IDOR because all identities get identical content on a non-object endpoint
        assertThat(finding.verdict()).isEqualTo(Verdict.INCONCLUSIVE);
        assertThat(finding.confidence().value()).isLessThan(50);
    }

    @Test
    @DisplayName("Dynamic-value noise: Timestamps and CSRF tokens do not prevent accurate IDOR detection")
    void testDynamicValueNoiseTolerated() {
        HttpRequest ownerReq = HttpRequest.builder()
                .method("GET")
                .url("https://example.com/api/documents/10")
                .path("/api/documents/10")
                .build();

        HttpResponse ownerRes = HttpResponse.builder()
                .statusCode(200)
                .header("Date", "Tue, 15 Nov 2026 10:00:00 GMT")
                .body("""
                        {
                          "id": 10,
                          "title": "Secret Strategy",
                          "timestamp": 1699990000000,
                          "csrf": "owner-csrf-token-1111",
                          "created_at": "2026-11-06T10:00:00Z"
                        }
                        """)
                .build();

        HttpResponse attackerRes = HttpResponse.builder()
                .statusCode(200)
                .header("Date", "Tue, 15 Nov 2026 10:01:00 GMT")
                .body("""
                        {
                          "id": 10,
                          "title": "Secret Strategy",
                          "timestamp": 1699990060000,
                          "csrf": "attacker-csrf-token-2222",
                          "created_at": "2026-11-06T10:01:00Z"
                        }
                        """)
                .build();

        HttpResponse anonRes = HttpResponse.builder().statusCode(401).body("{\"error\": \"Unauthorized\"}").build();

        ExchangePair exchange = new ExchangePair(ownerReq, ownerRes, attackerRes, anonRes);
        AuthDiffFinding finding = classifier.classify(exchange);

        assertThat(finding.verdict()).isEqualTo(Verdict.LIKELY_IDOR_BOLA);
        assertThat(finding.confidence().value()).isGreaterThanOrEqualTo(85);
    }
}
