package io.github.authdiff.core.redact;

import io.github.authdiff.core.model.HttpRequest;
import io.github.authdiff.core.model.HttpResponse;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class CredentialRedactorTest {

    @Test
    @DisplayName("Redacts sensitive authorization headers and cookies from requests")
    void testRequestRedaction() {
        HttpRequest req = HttpRequest.builder()
                .method("GET")
                .url("https://example.com/api/user?token=secret123&sort=asc")
                .header("Authorization", "Bearer eyJhbGciOi...")
                .header("Cookie", "session=supersecretcookie; uid=1")
                .header("X-Api-Key", "api-key-999")
                .header("Accept", "application/json")
                .queryParam("token", "secret123")
                .queryParam("sort", "asc")
                .cookie("session", "supersecretcookie")
                .build();

        HttpRequest redacted = CredentialRedactor.redact(req);

        // Sensitive headers are redacted
        assertThat(redacted.headers().get("Authorization")).containsExactly("[REDACTED]");
        assertThat(redacted.headers().get("Cookie")).containsExactly("[REDACTED]");
        assertThat(redacted.headers().get("X-Api-Key")).containsExactly("[REDACTED]");

        // Non-sensitive header preserved
        assertThat(redacted.headers().get("Accept")).containsExactly("application/json");

        // Cookies redacted
        assertThat(redacted.cookies().get("session")).isEqualTo("[REDACTED]");

        // Sensitive query parameter redacted
        assertThat(redacted.queryParams().get("token")).containsExactly("[REDACTED]");
        assertThat(redacted.queryParams().get("sort")).containsExactly("asc");
    }

    @Test
    @DisplayName("Redacts Set-Cookie headers in responses")
    void testResponseRedaction() {
        HttpResponse res = HttpResponse.builder()
                .statusCode(200)
                .header("Set-Cookie", "session_id=abcdef; Secure; HttpOnly")
                .header("Content-Type", "application/json")
                .cookie("session_id", "abcdef")
                .build();

        HttpResponse redacted = CredentialRedactor.redact(res);

        assertThat(redacted.headers().get("Set-Cookie")).containsExactly("[REDACTED]");
        assertThat(redacted.headers().get("Content-Type")).containsExactly("application/json");
        assertThat(redacted.cookies().get("session_id")).isEqualTo("[REDACTED]");
    }
}
