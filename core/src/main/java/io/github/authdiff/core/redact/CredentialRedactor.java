package io.github.authdiff.core.redact;

import io.github.authdiff.core.model.HttpRequest;
import io.github.authdiff.core.model.HttpResponse;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Redacts sensitive credentials (Authorization headers, cookies, bearer tokens, API keys)
 * from requests, responses, and exported reports to prevent accidental credential leakage.
 */
public final class CredentialRedactor {

    private static final String REDACTED_MARKER = "[REDACTED]";

    private static final Set<String> SENSITIVE_HEADERS = Set.of(
            "authorization", "proxy-authorization", "cookie", "set-cookie",
            "x-api-key", "api-key", "apikey", "x-auth-token", "x-access-token",
            "token", "session-token", "x-session-id"
    );

    private static final Pattern SENSITIVE_PARAM_PATTERN = Pattern.compile(
            "(?i)^(token|access_token|refresh_token|api_key|apikey|secret|password|auth|bearer)$"
    );

    private CredentialRedactor() {}

    public static HttpRequest redact(HttpRequest request) {
        if (request == null) return null;

        Map<String, List<String>> redactedHeaders = new LinkedHashMap<>();
        for (Map.Entry<String, List<String>> entry : request.headers().entrySet()) {
            String name = entry.getKey();
            if (isSensitiveHeader(name)) {
                redactedHeaders.put(name, List.of(REDACTED_MARKER));
            } else {
                redactedHeaders.put(name, new ArrayList<>(entry.getValue()));
            }
        }

        Map<String, String> redactedCookies = new LinkedHashMap<>();
        for (String cookieName : request.cookies().keySet()) {
            redactedCookies.put(cookieName, REDACTED_MARKER);
        }

        Map<String, List<String>> redactedQuery = new LinkedHashMap<>();
        for (Map.Entry<String, List<String>> entry : request.queryParams().entrySet()) {
            String paramName = entry.getKey();
            if (SENSITIVE_PARAM_PATTERN.matcher(paramName).matches()) {
                redactedQuery.put(paramName, List.of(REDACTED_MARKER));
            } else {
                redactedQuery.put(paramName, new ArrayList<>(entry.getValue()));
            }
        }

        return HttpRequest.builder()
                .method(request.method())
                .url(request.url())
                .path(request.path())
                .headers(redactedHeaders)
                .cookies(redactedCookies)
                .queryParams(redactedQuery)
                .body(request.body())
                .build();
    }

    public static HttpResponse redact(HttpResponse response) {
        if (response == null) return null;

        Map<String, List<String>> redactedHeaders = new LinkedHashMap<>();
        for (Map.Entry<String, List<String>> entry : response.headers().entrySet()) {
            String name = entry.getKey();
            if (isSensitiveHeader(name)) {
                redactedHeaders.put(name, List.of(REDACTED_MARKER));
            } else {
                redactedHeaders.put(name, new ArrayList<>(entry.getValue()));
            }
        }

        Map<String, String> redactedCookies = new LinkedHashMap<>();
        for (String cookieName : response.cookies().keySet()) {
            redactedCookies.put(cookieName, REDACTED_MARKER);
        }

        return HttpResponse.builder()
                .statusCode(response.statusCode())
                .headers(redactedHeaders)
                .cookies(redactedCookies)
                .body(response.body())
                .responseTimeMs(response.responseTimeMs())
                .build();
    }

    public static boolean isSensitiveHeader(String headerName) {
        if (headerName == null) return false;
        return SENSITIVE_HEADERS.contains(headerName.trim().toLowerCase());
    }

    public static String redactHeaderValue(String name, String value) {
        if (isSensitiveHeader(name)) {
            return REDACTED_MARKER;
        }
        return value;
    }
}
