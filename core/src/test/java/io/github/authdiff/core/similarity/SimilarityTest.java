package io.github.authdiff.core.similarity;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.within;

class SimilarityTest {

    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    @DisplayName("TokenSetJaccard handles identical, partially overlapping, and disjoint inputs")
    void testTokenSetJaccard() {
        // Identical strings
        assertThat(TokenSetJaccardSimilarity.compute("user profile id 100", "user profile id 100"))
                .isCloseTo(1.0, within(0.0001));

        // Reordered tokens (Jaccard token set is order-invariant)
        assertThat(TokenSetJaccardSimilarity.compute("user profile id 100", "id 100 profile user"))
                .isCloseTo(1.0, within(0.0001));

        // Partial overlap
        double partial = TokenSetJaccardSimilarity.compute("apple orange banana", "banana orange cherry");
        // union = {apple, orange, banana, cherry} (4), intersection = {orange, banana} (2) -> 2/4 = 0.5
        assertThat(partial).isCloseTo(0.5, within(0.0001));

        // Empty strings
        assertThat(TokenSetJaccardSimilarity.compute("", "")).isEqualTo(1.0);
        assertThat(TokenSetJaccardSimilarity.compute("hello", "")).isEqualTo(0.0);
    }

    @Test
    @DisplayName("JsonStructuralComparator accurately evaluates key-set and value overlap")
    void testJsonStructuralComparator() throws Exception {
        JsonNode jsonA = mapper.readTree("""
                {
                  "user": {
                    "id": 1,
                    "name": "Alice",
                    "role": "admin"
                  }
                }
                """);

        JsonNode jsonBIdentical = mapper.readTree("""
                {
                  "user": {
                    "role": "admin",
                    "id": 1,
                    "name": "Alice"
                  }
                }
                """);

        JsonNode jsonBDifferentValues = mapper.readTree("""
                {
                  "user": {
                    "id": 2,
                    "name": "Bob",
                    "role": "user"
                  }
                }
                """);

        JsonNode jsonBError = mapper.readTree("""
                {
                  "error": "Forbidden",
                  "code": 403
                }
                """);

        var resIdentical = JsonStructuralComparator.compare(jsonA, jsonBIdentical);
        assertThat(resIdentical.keySetOverlap()).isEqualTo(1.0);
        assertThat(resIdentical.valueOverlap()).isEqualTo(1.0);
        assertThat(resIdentical.compositeSimilarity()).isEqualTo(1.0);

        var resSameKeysDiffValues = JsonStructuralComparator.compare(jsonA, jsonBDifferentValues);
        assertThat(resSameKeysDiffValues.keySetOverlap()).isEqualTo(1.0);
        assertThat(resSameKeysDiffValues.valueOverlap()).isEqualTo(0.0);
        // composite = 0.4 * 1.0 + 0.6 * 0.0 = 0.4
        assertThat(resSameKeysDiffValues.compositeSimilarity()).isCloseTo(0.4, within(0.0001));

        var resError = JsonStructuralComparator.compare(jsonA, jsonBError);
        assertThat(resError.keySetOverlap()).isEqualTo(0.0);
        assertThat(resError.compositeSimilarity()).isEqualTo(0.0);
    }

    @Test
    @DisplayName("BodyLengthRatio handles empty, equal, and asymmetric lengths")
    void testBodyLengthRatio() {
        assertThat(BodyLengthRatio.compute(0, 0)).isEqualTo(1.0);
        assertThat(BodyLengthRatio.compute(500, 500)).isEqualTo(1.0);
        assertThat(BodyLengthRatio.compute(50, 100)).isCloseTo(0.5, within(0.0001));
        assertThat(BodyLengthRatio.compute(0, 100)).isEqualTo(0.0);
    }
}
