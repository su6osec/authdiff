package io.github.authdiff.core.detection;

import io.github.authdiff.core.model.HttpRequest;
import io.github.authdiff.core.model.IdentifierRef;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class IdentifierDetectorTest {

    @Test
    @DisplayName("Detects numeric and UUID identifiers in path")
    void testPathIdentifierDetection() {
        HttpRequest reqNumeric = HttpRequest.builder()
                .url("https://example.com/api/v1/baskets/42")
                .path("/api/v1/baskets/42")
                .build();

        List<IdentifierRef> ids1 = IdentifierDetector.detect(reqNumeric);
        assertThat(ids1).hasSize(1);
        assertThat(ids1.get(0).location()).isEqualTo(IdentifierRef.Location.PATH);
        assertThat(ids1.get(0).value()).isEqualTo("42");
        assertThat(ids1.get(0).type()).isEqualTo(IdentifierRef.IdentifierType.NUMERIC);

        HttpRequest reqUuid = HttpRequest.builder()
                .url("https://example.com/api/users/9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d/orders")
                .path("/api/users/9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d/orders")
                .build();

        List<IdentifierRef> ids2 = IdentifierDetector.detect(reqUuid);
        assertThat(ids2).hasSize(1);
        assertThat(ids2.get(0).value()).isEqualTo("9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d");
        assertThat(ids2.get(0).type()).isEqualTo(IdentifierRef.IdentifierType.UUID);
    }

    @Test
    @DisplayName("Detects object identifiers in query parameters")
    void testQueryIdentifierDetection() {
        HttpRequest req = HttpRequest.builder()
                .url("https://example.com/api/download?order_id=1024&format=pdf")
                .queryParam("order_id", "1024")
                .queryParam("format", "pdf")
                .build();

        List<IdentifierRef> ids = IdentifierDetector.detect(req);
        assertThat(ids).hasSize(1);
        assertThat(ids.get(0).location()).isEqualTo(IdentifierRef.Location.QUERY);
        assertThat(ids.get(0).nameOrSegment()).isEqualTo("order_id");
        assertThat(ids.get(0).value()).isEqualTo("1024");
    }

    @Test
    @DisplayName("Detects object identifiers in JSON request body")
    void testBodyIdentifierDetection() {
        HttpRequest req = HttpRequest.builder()
                .method("POST")
                .url("https://example.com/api/checkout")
                .body("{\"basketId\": 88, \"coupon\": \"DISCOUNT10\"}")
                .build();

        List<IdentifierRef> ids = IdentifierDetector.detect(req);
        assertThat(ids).hasSize(1);
        assertThat(ids.get(0).location()).isEqualTo(IdentifierRef.Location.BODY);
        assertThat(ids.get(0).nameOrSegment()).isEqualTo("basketId");
        assertThat(ids.get(0).value()).isEqualTo("88");
    }
}
