package io.github.authdiff.burp.engine;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import io.github.authdiff.burp.MontoyaModelConverter;
import io.github.authdiff.burp.model.BurpExchangeRecord;
import io.github.authdiff.burp.ui.AuthDiffTableModel;
import io.github.authdiff.core.detection.AuthDiffClassifier;
import io.github.authdiff.core.model.AuthDiffFinding;
import io.github.authdiff.core.model.ExchangePair;

import javax.swing.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Background execution engine that processes replayed requests off the UI thread.
 */
public final class AuthDiffWorkerPool {

    private static final Set<String> SAFE_METHODS = Set.of("GET", "HEAD", "OPTIONS");

    private final MontoyaApi api;
    private final AuthDiffTableModel tableModel;
    private final ExecutorService executor;
    private final AtomicInteger sequenceCounter = new AtomicInteger(1);

    private volatile String attackerHeadersText = "";
    private volatile String allowlistText = "";
    private volatile boolean testAnonymous = true;
    private volatile boolean onlySafeMethods = true;
    private volatile boolean onlyInScope = true;
    private volatile double requestsPerSecond = 2.0;

    private long lastRequestTimestamp = 0;

    public AuthDiffWorkerPool(MontoyaApi api, AuthDiffTableModel tableModel) {
        this.api = api;
        this.tableModel = tableModel;
        this.executor = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "authdiff-worker");
            t.setDaemon(true);
            return t;
        });
    }

    public void updateConfig(
            String attackerHeadersText,
            String allowlistText,
            boolean testAnonymous,
            boolean onlySafeMethods,
            boolean onlyInScope,
            double requestsPerSecond
    ) {
        this.attackerHeadersText = attackerHeadersText;
        this.allowlistText = allowlistText;
        this.testAnonymous = testAnonymous;
        this.onlySafeMethods = onlySafeMethods;
        this.onlyInScope = onlyInScope;
        this.requestsPerSecond = Math.max(0.2, requestsPerSecond);
    }

    public void enqueue(List<HttpRequestResponse> items) {
        if (items == null || items.isEmpty()) return;

        executor.submit(() -> {
            for (HttpRequestResponse item : items) {
                if (Thread.currentThread().isInterrupted()) {
                    break;
                }
                processItem(item);
            }
        });
    }

    private void processItem(HttpRequestResponse ownerItem) {
        if (ownerItem == null || ownerItem.request() == null || ownerItem.response() == null) {
            return;
        }

        HttpRequest ownerReq = ownerItem.request();
        String url = ownerReq.url();
        String method = ownerReq.method().toUpperCase();

        // 1. Scope restriction
        if (onlyInScope && !api.scope().isInScope(url)) {
            api.logging().logToOutput("[authdiff] Refused out-of-scope request: " + method + " " + url);
            return;
        }

        // 2. Safe method guard
        if (onlySafeMethods && !SAFE_METHODS.contains(method)) {
            api.logging().logToOutput("[authdiff] Refused state-changing method " + method + " on " + url + " (unsafe methods disabled)");
            return;
        }

        try {
            // Build Attacker Request
            Map<String, String> attackerHeaders = parseHeaders(attackerHeadersText);
            HttpRequest attackerReq = prepareRequest(ownerReq, attackerHeaders, false);

            throttle();
            HttpRequestResponse attackerItem = api.http().sendRequest(attackerReq);

            // Build Anon Request (optional)
            HttpRequestResponse anonItem = null;
            if (testAnonymous) {
                HttpRequest anonReq = prepareRequest(ownerReq, Collections.emptyMap(), true);
                throttle();
                anonItem = api.http().sendRequest(anonReq);
            }

            // Convert to core models and classify
            io.github.authdiff.core.model.HttpRequest coreReq = MontoyaModelConverter.toCoreRequest(ownerReq);
            io.github.authdiff.core.model.HttpResponse coreOwnerRes = MontoyaModelConverter.toCoreResponse(ownerItem.response());
            io.github.authdiff.core.model.HttpResponse coreAttackerRes = MontoyaModelConverter.toCoreResponse(attackerItem.response());
            io.github.authdiff.core.model.HttpResponse coreAnonRes = anonItem != null ? MontoyaModelConverter.toCoreResponse(anonItem.response()) : null;

            ExchangePair exchange = new ExchangePair(coreReq, coreOwnerRes, coreAttackerRes, coreAnonRes);

            List<String> allowlistGlobs = new ArrayList<>();
            if (allowlistText != null && !allowlistText.isBlank()) {
                for (String g : allowlistText.split(",")) {
                    if (!g.isBlank()) allowlistGlobs.add(g.trim());
                }
            }

            AuthDiffClassifier classifier = new AuthDiffClassifier(new AuthDiffClassifier.Options(allowlistGlobs, 0.70, 0.85));
            AuthDiffFinding finding = classifier.classify(exchange);

            BurpExchangeRecord record = new BurpExchangeRecord(
                    sequenceCounter.getAndIncrement(),
                    finding,
                    ownerItem,
                    attackerItem,
                    anonItem
            );

            SwingUtilities.invokeLater(() -> tableModel.addRecord(record));

        } catch (Exception e) {
            api.logging().logToError("[authdiff] Error replaying " + method + " " + url + ": " + e.getMessage());
        }
    }

    private HttpRequest prepareRequest(HttpRequest original, Map<String, String> customHeaders, boolean anonymous) {
        HttpRequest req = original;

        // Remove owner credentials
        req = req.withRemovedHeader("Authorization")
                .withRemovedHeader("authorization")
                .withRemovedHeader("Cookie")
                .withRemovedHeader("cookie")
                .withRemovedHeader("X-Api-Key")
                .withRemovedHeader("x-api-key")
                .withRemovedHeader("X-Auth-Token")
                .withRemovedHeader("x-auth-token");

        // Apply custom attacker credentials
        if (!anonymous && customHeaders != null) {
            for (Map.Entry<String, String> entry : customHeaders.entrySet()) {
                req = req.withAddedHeader(entry.getKey(), entry.getValue());
            }
        }

        return req;
    }

    private void throttle() throws InterruptedException {
        long delayMs = requestsPerSecond > 0 ? (long) (1000.0 / requestsPerSecond) : 500;
        long now = System.currentTimeMillis();
        long elapsed = now - lastRequestTimestamp;
        if (elapsed < delayMs) {
            Thread.sleep(delayMs - elapsed);
        }
        lastRequestTimestamp = System.currentTimeMillis();
    }

    private Map<String, String> parseHeaders(String text) {
        if (text == null || text.isBlank()) return Collections.emptyMap();
        Map<String, String> map = new HashMap<>();
        String[] lines = text.split("\\r?\\n");
        for (String line : lines) {
            int colon = line.indexOf(':');
            if (colon > 0) {
                map.put(line.substring(0, colon).trim(), line.substring(colon + 1).trim());
            }
        }
        return map;
    }

    public void shutdown() {
        executor.shutdownNow();
    }
}
