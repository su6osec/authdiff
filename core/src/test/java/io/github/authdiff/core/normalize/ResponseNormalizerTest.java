package io.github.authdiff.core.normalize;

import io.github.authdiff.core.model.HttpResponse;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class ResponseNormalizerTest {

    @Test
    @DisplayName("Normalizes dynamic-value noise such as ISO8601 timestamps and volatile headers")
    void testVolatileTokensStripped() {
        HttpResponse res = HttpResponse.builder()
                .statusCode(200)
                .header("Content-Type", "application/json")
                .header("Date", "Tue, 15 Nov 2026 12:45:00 GMT")
                .header("ETag", "W/\"123456\"")
                .header("X-Request-Id", "req-abcdef-987654")
                .header("Traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
                .body("""
                        {
                          "order_id": 42,
                          "timestamp": 1699999999000,
                          "csrf_token": "secret-csrf-token-1234",
                          "created_at": "2026-11-06T12:00:00Z",
                          "items": ["apple", "banana"]
                        }
                        """)
                .build();

        ResponseNormalizer.NormalizedResponse norm = ResponseNormalizer.normalize(res);

        // Volatile headers stripped
        assertThat(norm.headers()).doesNotContainKeys("date", "etag", "x-request-id", "traceparent");
        assertThat(norm.headers()).containsKey("content-type");

        // Volatile fields canonicalized to placeholders
        assertThat(norm.body()).contains("<VOLATILE>");
        assertThat(norm.body()).doesNotContain("secret-csrf-token-1234");
        assertThat(norm.body()).contains("\"order_id\":42");
    }

    @Test
    @DisplayName("Normalizes JSON key ordering into canonical sorted form")
    void testJsonKeyOrderingCanonicalized() {
        HttpResponse res1 = HttpResponse.builder()
                .body("{\"z\": 1, \"a\": 2}")
                .build();

        HttpResponse res2 = HttpResponse.builder()
                .body("{\n  \"a\": 2,\n  \"z\": 1\n}")
                .build();

        ResponseNormalizer.NormalizedResponse norm1 = ResponseNormalizer.normalize(res1);
        ResponseNormalizer.NormalizedResponse norm2 = ResponseNormalizer.normalize(res2);

        assertThat(norm1.body()).isEqualTo(norm2.body());
    }

    @Test
    @DisplayName("Collapses irregular whitespace in plain text / HTML responses")
    void testWhitespaceNormalization() {
        String input = "<html>\n\n   <body>\n      <h1>  Welcome   </h1>\n   </body></html>";
        String normalized = ResponseNormalizer.normalizeText(input);

        assertThat(normalized).isEqualTo("<html> <body> <h1> Welcome </h1> </body></html>");
    }
}
