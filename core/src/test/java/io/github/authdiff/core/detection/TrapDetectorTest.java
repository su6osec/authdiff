package io.github.authdiff.core.detection;

import io.github.authdiff.core.model.HttpResponse;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class TrapDetectorTest {

    @Test
    @DisplayName("Detects 200 OK responses containing access-denied or error JSON")
    void test200WithErrorJson() {
        HttpResponse res = HttpResponse.builder()
                .statusCode(200)
                .body("{\"error\": \"Unauthorized: You do not own this basket\", \"code\": 403}")
                .build();

        assertThat(TrapDetector.is200WithErrorBody(res)).isTrue();
    }

    @Test
    @DisplayName("Detects 200 OK responses containing plaintext access-denied messages")
    void test200WithErrorText() {
        HttpResponse res = HttpResponse.builder()
                .statusCode(200)
                .body("Access Denied: You must log in to view this invoice.")
                .build();

        assertThat(TrapDetector.is200WithErrorBody(res)).isTrue();
    }

    @Test
    @DisplayName("Does not false positive on legitimate 200 OK data responses")
    void test200LegitimateResponse() {
        HttpResponse res = HttpResponse.builder()
                .statusCode(200)
                .body("{\"status\": \"success\", \"basket\": {\"id\": 1, \"items\": [\"juice\"]}}")
                .build();

        assertThat(TrapDetector.is200WithErrorBody(res)).isFalse();
    }

    @Test
    @DisplayName("Detects HTTP 302/307 redirects to login and authentication pages")
    void testLoginRedirect() {
        HttpResponse redirectRes = HttpResponse.builder()
                .statusCode(302)
                .header("Location", "/auth/login?next=/account")
                .build();

        assertThat(TrapDetector.isLoginRedirect(redirectRes)).isTrue();

        HttpResponse normalRedirect = HttpResponse.builder()
                .statusCode(301)
                .header("Location", "https://example.com/api/v2/items")
                .build();

        assertThat(TrapDetector.isLoginRedirect(normalRedirect)).isFalse();
    }

    @Test
    @DisplayName("Detects SPA HTML shells returned by client-side routing servers")
    void testSpaShellDetection() {
        HttpResponse spaRes = HttpResponse.builder()
                .statusCode(200)
                .header("Content-Type", "text/html; charset=utf-8")
                .body("""
                        <!doctype html>
                        <html>
                          <head><title>App</title></head>
                          <body>
                            <div id="root"></div>
                            <script src="/static/js/bundle.js"></script>
                          </body>
                        </html>
                        """)
                .build();

        assertThat(TrapDetector.isSpaShell(spaRes)).isTrue();
    }
}
