package io.github.authdiff.core.detection;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.authdiff.core.model.HttpResponse;

import java.util.regex.Pattern;

/**
 * Detects deceptive server responses:
 * - 200 OK containing an access-denied or error payload.
 * - Redirects to authentication/login endpoints (302/303/307).
 * - Generic SPA (Single Page Application) shells returned on all routes.
 */
public final class TrapDetector {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final Pattern ERROR_WORDS = Pattern.compile(
            "(?i)\\b(unauthorized|access denied|forbidden|not allowed|authentication required|invalid token|" +
                    "session expired|permission denied|not authorized|login required)\\b"
    );

    private static final Pattern LOGIN_PATH_PATTERN = Pattern.compile(
            "(?i).*(login|signin|sign-in|authenticate|oauth|auth).*$"
    );

    private static final Pattern SPA_MARKERS = Pattern.compile(
            "(?i)(<div\\s+id=[\"']root[\"']\\s*>|<app-root\\b|<div\\s+id=[\"']app[\"']\\s*>|<script[^>]+src=[\"'][^\"']*(?:bundle|chunk|main|vendor)\\.js[\"'])"
    );

    private TrapDetector() {}

    /**
     * Checks if response has status 200 but represents a logical error or access denial.
     */
    public static boolean is200WithErrorBody(HttpResponse response) {
        if (response == null || response.statusCode() != 200) {
            return false;
        }

        String body = response.bodyString().trim();
        if (body.isEmpty()) {
            return false;
        }

        // Check if small JSON response with error field
        try {
            JsonNode node = MAPPER.readTree(body);
            if (node.isObject()) {
                if (node.has("error") || node.has("errors") || node.has("errorCode") || node.has("errorMessage")) {
                    return true;
                }
                if (node.has("status") && "error".equalsIgnoreCase(node.get("status").asText())) {
                    return true;
                }
                if (node.has("success") && !node.get("success").asBoolean()) {
                    return true;
                }
            }
        } catch (Exception ignored) {
            // Not JSON
        }

        // Check if short body (< 1500 chars) contains explicit error keywords
        if (body.length() < 1500 && ERROR_WORDS.matcher(body).find()) {
            return true;
        }

        return false;
    }

    /**
     * Checks if response is a redirect to a login/auth page.
     */
    public static boolean isLoginRedirect(HttpResponse response) {
        if (response == null || !response.isRedirect()) {
            return false;
        }
        String location = response.headerFirstValue("Location");
        if (location == null || location.isBlank()) {
            return false;
        }
        return LOGIN_PATH_PATTERN.matcher(location).matches();
    }

    /**
     * Checks if the response body is an SPA HTML shell.
     */
    public static boolean isSpaShell(HttpResponse response) {
        if (response == null) return false;
        String contentType = response.headerFirstValue("Content-Type");
        String body = response.bodyString();

        if (body.isEmpty()) return false;

        boolean isHtml = (contentType != null && contentType.toLowerCase().contains("text/html")) ||
                body.trim().toLowerCase().startsWith("<!doctype html") ||
                body.trim().toLowerCase().startsWith("<html");

        if (!isHtml) {
            return false;
        }

        // An SPA shell typically contains root mount points and bundle scripts, but minimal initial DOM text
        return SPA_MARKERS.matcher(body).find();
    }
}
