package io.github.authdiff.cli.replay;

import io.github.authdiff.core.model.HttpRequest;
import io.github.authdiff.core.model.HttpResponse;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class HttpReplayerSafetyTest {

    @Test
    @DisplayName("Safety Guard: Enforces strict host scope and rejects out-of-scope requests")
    void testScopeRestriction() {
        HttpReplayer.Config config = new HttpReplayer.Config(
                Set.of("juice.local", "api.juice.local"),
                Collections.emptyMap(),
                true,
                false,
                2.0,
                100,
                Duration.ofSeconds(2)
        );

        HttpReplayer replayer = new HttpReplayer(config);

        assertThat(replayer.isInScope("https://juice.local/rest/basket/1")).isTrue();
        assertThat(replayer.isInScope("https://api.juice.local/v1/user")).isTrue();

        // Out-of-scope targets rejected
        assertThat(replayer.isInScope("https://evil.com/steal")).isFalse();
        assertThat(replayer.isInScope("https://attacker.local/api")).isFalse();
    }

    @Test
    @DisplayName("Safety Guard: Skips state-changing HTTP methods when unsafe methods are disabled")
    void testSafeMethodsDefault() {
        HttpReplayer.Config config = new HttpReplayer.Config(
                Set.of("juice.local"),
                Collections.emptyMap(),
                true,
                false, // allowUnsafeMethods is false
                2.0,
                100,
                Duration.ofSeconds(2)
        );

        HttpReplayer replayer = new HttpReplayer(config);

        HttpRequest deleteReq = HttpRequest.builder()
                .method("DELETE")
                .url("https://juice.local/api/users/1")
                .build();

        HttpRequest postReq = HttpRequest.builder()
                .method("POST")
                .url("https://juice.local/api/orders")
                .body("{\"order\": 1}")
                .build();

        HttpResponse dummyRes = HttpResponse.builder().statusCode(200).build();

        var exchanges = replayer.replayAll(List.of(deleteReq, postReq), List.of(dummyRes, dummyRes));

        // State changing methods must NOT be replayed
        assertThat(exchanges).isEmpty();
    }
}
