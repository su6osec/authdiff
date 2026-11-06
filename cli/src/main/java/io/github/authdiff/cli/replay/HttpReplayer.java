package io.github.authdiff.cli.replay;

import io.github.authdiff.core.model.ExchangePair;
import io.github.authdiff.core.model.HttpRequest;
import io.github.authdiff.core.model.HttpResponse;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse.BodyHandlers;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Replays captured requests with attacker credentials and anonymous identity against live targets.
 * Enforces strict safety defaults:
 * - Safe HTTP methods (GET, HEAD, OPTIONS) only by default
 * - Strict target host scope checking
 * - Built-in rate limiting
 * - Hard request count cap
 */
public final class HttpReplayer {

    private static final Set<String> SAFE_METHODS = Set.of("GET", "HEAD", "OPTIONS");

    public record Config(
            Set<String> scopeHosts,
            Map<String, String> attackerHeaders,
            boolean testAnonymous,
            boolean allowUnsafeMethods,
            double requestsPerSecond,
            int maxTotalRequests,
            Duration timeout
    ) {
        public static Config defaults(Set<String> scopeHosts, Map<String, String> attackerHeaders) {
            return new Config(
                    scopeHosts,
                    attackerHeaders,
                    true,
                    false, // unsafe methods disabled by default
                    2.0,   // 2 req/s rate limit
                    500,   // 500 total request cap
                    Duration.ofSeconds(10)
            );
        }
    }

    private final Config config;
    private final HttpClient client;
    private final long delayBetweenRequestsMs;
    private long lastRequestTimestamp = 0;
    private int totalReplaysExecuted = 0;

    public HttpReplayer(Config config) {
        this.config = config;
        this.delayBetweenRequestsMs = config.requestsPerSecond() > 0
                ? (long) (1000.0 / config.requestsPerSecond())
                : 500;
        this.client = HttpClient.newBuilder()
                .connectTimeout(config.timeout())
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    public List<ExchangePair> replayAll(List<HttpRequest> ownerRequests, List<HttpResponse> ownerResponses) {
        List<ExchangePair> results = new ArrayList<>();
        int count = Math.min(ownerRequests.size(), ownerResponses.size());

        for (int i = 0; i < count; i++) {
            if (totalReplaysExecuted >= config.maxTotalRequests()) {
                System.err.printf("[!] Reached maximum replay cap of %d requests. Stopping.%n", config.maxTotalRequests());
                break;
            }

            HttpRequest req = ownerRequests.get(i);
            HttpResponse ownerRes = ownerResponses.get(i);

            // 1. Verify Scope
            if (!isInScope(req.url())) {
                System.err.printf("[-] Skipping out-of-scope request: %s %s%n", req.method(), req.url());
                continue;
            }

            // 2. Verify Safe Method
            if (!config.allowUnsafeMethods() && !SAFE_METHODS.contains(req.method().toUpperCase())) {
                System.err.printf("[-] Skipping state-changing method %s on %s (use --allow-unsafe-methods to enable)%n",
                        req.method(), req.url());
                continue;
            }

            try {
                // Replay as Attacker
                HttpResponse attackerRes = executeRequest(req, config.attackerHeaders(), false);
                totalReplaysExecuted++;

                // Replay as Anon if enabled
                HttpResponse anonRes = null;
                if (config.testAnonymous()) {
                    if (totalReplaysExecuted < config.maxTotalRequests()) {
                        anonRes = executeRequest(req, Collections.emptyMap(), true);
                        totalReplaysExecuted++;
                    }
                }

                results.add(new ExchangePair(req, ownerRes, attackerRes, anonRes));
            } catch (Exception e) {
                System.err.printf("[!] Error replaying %s %s: %s%n", req.method(), req.url(), e.getMessage());
            }
        }

        return results;
    }

    public boolean isInScope(String rawUrl) {
        if (config.scopeHosts().isEmpty()) {
            return false;
        }
        try {
            URI uri = URI.create(rawUrl);
            String host = uri.getHost();
            if (host == null) return false;

            for (String scope : config.scopeHosts()) {
                if (scope.equalsIgnoreCase(host)) {
                    return true;
                }
                if (scope.startsWith(".") && host.endsWith(scope)) {
                    return true;
                }
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    private HttpResponse executeRequest(HttpRequest original, Map<String, String> credentialHeaders, boolean anonymous)
            throws IOException, InterruptedException {

        throttle();

        URI uri = URI.create(original.url());
        java.net.http.HttpRequest.Builder builder = java.net.http.HttpRequest.newBuilder(uri)
                .timeout(config.timeout());

        // Copy non-credential headers from original
        for (Map.Entry<String, List<String>> header : original.headers().entrySet()) {
            String name = header.getKey();
            if (isAuthHeader(name)) {
                continue; // Strip owner credentials
            }
            if (name.equalsIgnoreCase("content-length") || name.equalsIgnoreCase("host")) {
                continue; // Let HTTP client calculate these
            }
            for (String val : header.getValue()) {
                try {
                    builder.header(name, val);
                } catch (IllegalArgumentException ignored) {
                    // Skip restricted system headers
                }
            }
        }

        // Apply attacker credentials if not anonymous
        if (!anonymous && credentialHeaders != null) {
            for (Map.Entry<String, String> entry : credentialHeaders.entrySet()) {
                builder.setHeader(entry.getKey(), entry.getValue());
            }
        }

        // Set HTTP method & body
        String method = original.method().toUpperCase();
        byte[] body = original.body();
        if ("GET".equals(method)) {
            builder.GET();
        } else if ("DELETE".equals(method)) {
            builder.DELETE();
        } else if ("POST".equals(method)) {
            builder.POST(body != null && body.length > 0 ? BodyPublishers.ofByteArray(body) : BodyPublishers.noBody());
        } else if ("PUT".equals(method)) {
            builder.PUT(body != null && body.length > 0 ? BodyPublishers.ofByteArray(body) : BodyPublishers.noBody());
        } else {
            builder.method(method, body != null && body.length > 0 ? BodyPublishers.ofByteArray(body) : BodyPublishers.noBody());
        }

        long start = System.currentTimeMillis();
        java.net.http.HttpResponse<byte[]> response = client.send(builder.build(), BodyHandlers.ofByteArray());
        long elapsed = System.currentTimeMillis() - start;

        HttpResponse.Builder resBuilder = HttpResponse.builder()
                .statusCode(response.statusCode())
                .responseTimeMs(elapsed)
                .body(response.body());

        for (Map.Entry<String, List<String>> h : response.headers().map().entrySet()) {
            for (String v : h.getValue()) {
                resBuilder.header(h.getKey(), v);
            }
        }

        return resBuilder.build();
    }

    private void throttle() throws InterruptedException {
        long now = System.currentTimeMillis();
        long elapsed = now - lastRequestTimestamp;
        if (elapsed < delayBetweenRequestsMs) {
            Thread.sleep(delayBetweenRequestsMs - elapsed);
        }
        lastRequestTimestamp = System.currentTimeMillis();
    }

    private static boolean isAuthHeader(String name) {
        String lower = name.toLowerCase();
        return lower.equals("authorization") ||
                lower.equals("cookie") ||
                lower.equals("x-api-key") ||
                lower.equals("api-key") ||
                lower.equals("x-auth-token") ||
                lower.equals("token");
    }
}
