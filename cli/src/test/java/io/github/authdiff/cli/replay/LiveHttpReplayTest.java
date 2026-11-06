package io.github.authdiff.cli.replay;

import com.sun.net.httpserver.HttpServer;
import io.github.authdiff.core.detection.AuthDiffClassifier;
import io.github.authdiff.core.model.AuthDiffFinding;
import io.github.authdiff.core.model.ExchangePair;
import io.github.authdiff.core.model.HttpRequest;
import io.github.authdiff.core.model.HttpResponse;
import io.github.authdiff.core.model.Verdict;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class LiveHttpReplayTest {

    private static HttpServer server;
    private static int port;

    @BeforeAll
    static void startServer() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        port = server.getAddress().getPort();

        // 1. Vulnerable Basket endpoint (IDOR)
        server.createContext("/api/basket/10", exchange -> {
            String auth = exchange.getRequestHeaders().getFirst("Authorization");
            if ("Bearer attacker_token".equals(auth) || "Bearer owner_token".equals(auth)) {
                byte[] body = "{\"basket\": 10, \"items\": [\"Orange Juice\"], \"owner\": \"alice\"}".getBytes();
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.sendResponseHeaders(200, body.length);
                try (OutputStream os = exchange.getResponseBody()) { os.write(body); }
            } else {
                byte[] body = "{\"error\": \"Unauthorized\"}".getBytes();
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.sendResponseHeaders(401, body.length);
                try (OutputStream os = exchange.getResponseBody()) { os.write(body); }
            }
        });

        // 2. Properly protected Account endpoint (Enforced)
        server.createContext("/api/account/10", exchange -> {
            String auth = exchange.getRequestHeaders().getFirst("Authorization");
            if ("Bearer owner_token".equals(auth)) {
                byte[] body = "{\"account\": 10, \"owner\": \"alice\", \"balance\": 500}".getBytes();
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.sendResponseHeaders(200, body.length);
                try (OutputStream os = exchange.getResponseBody()) { os.write(body); }
            } else if ("Bearer attacker_token".equals(auth)) {
                byte[] body = "{\"error\": \"Forbidden: not your account\"}".getBytes();
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.sendResponseHeaders(403, body.length);
                try (OutputStream os = exchange.getResponseBody()) { os.write(body); }
            } else {
                byte[] body = "{\"error\": \"Unauthorized\"}".getBytes();
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.sendResponseHeaders(401, body.length);
                try (OutputStream os = exchange.getResponseBody()) { os.write(body); }
            }
        });

        server.start();
    }

    @AfterAll
    static void stopServer() {
        if (server != null) {
            server.stop(0);
        }
    }

    @Test
    @DisplayName("Performs live HTTP network replay and accurately classifies IDOR and Enforced endpoints")
    void testLiveHttpReplay() {
        HttpReplayer.Config config = new HttpReplayer.Config(
                Set.of("127.0.0.1"),
                Map.of("Authorization", "Bearer attacker_token"),
                true,
                false,
                20.0,
                100,
                Duration.ofSeconds(3)
        );

        HttpReplayer replayer = new HttpReplayer(config);

        String basketUrl = "http://127.0.0.1:" + port + "/api/basket/10";
        HttpRequest basketOwnerReq = HttpRequest.builder()
                .method("GET")
                .url(basketUrl)
                .path("/api/basket/10")
                .header("Authorization", "Bearer owner_token")
                .build();
        HttpResponse basketOwnerRes = HttpResponse.builder()
                .statusCode(200)
                .body("{\"basket\": 10, \"items\": [\"Orange Juice\"], \"owner\": \"alice\"}")
                .build();

        String accountUrl = "http://127.0.0.1:" + port + "/api/account/10";
        HttpRequest accountOwnerReq = HttpRequest.builder()
                .method("GET")
                .url(accountUrl)
                .path("/api/account/10")
                .header("Authorization", "Bearer owner_token")
                .build();
        HttpResponse accountOwnerRes = HttpResponse.builder()
                .statusCode(200)
                .body("{\"account\": 10, \"owner\": \"alice\", \"balance\": 500}")
                .build();

        List<ExchangePair> exchanges = replayer.replayAll(
                List.of(basketOwnerReq, accountOwnerReq),
                List.of(basketOwnerRes, accountOwnerRes)
        );

        assertThat(exchanges).hasSize(2);

        AuthDiffClassifier classifier = new AuthDiffClassifier();

        // 1. Verify basket endpoint was classified as LIKELY_IDOR_BOLA over live network
        AuthDiffFinding basketFinding = classifier.classify(exchanges.get(0));
        assertThat(basketFinding.verdict()).isEqualTo(Verdict.LIKELY_IDOR_BOLA);
        assertThat(basketFinding.attackerStatusCode()).isEqualTo(200);
        assertThat(basketFinding.anonStatusCode()).contains(401);

        // 2. Verify account endpoint was classified as ENFORCED over live network
        AuthDiffFinding accountFinding = classifier.classify(exchanges.get(1));
        assertThat(accountFinding.verdict()).isEqualTo(Verdict.ENFORCED);
        assertThat(accountFinding.attackerStatusCode()).isEqualTo(403);
        assertThat(accountFinding.anonStatusCode()).contains(401);
    }
}
