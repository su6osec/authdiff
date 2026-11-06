package io.github.authdiff.core.normalize;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;
import io.github.authdiff.core.model.HttpResponse;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Pattern;

/**
 * Normalizes HTTP responses prior to comparison.
 * Eliminates volatile dynamic data (timestamps, session tokens, request IDs, nonces, ETags)
 * and structural whitespace differences.
 */
public final class ResponseNormalizer {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /**
     * Set of volatile headers that typically vary across requests regardless of authorization state.
     */
    private static final Set<String> VOLATILE_HEADERS = Set.of(
            "date", "etag", "last-modified", "expires",
            "x-request-id", "x-correlation-id", "x-trace-id", "traceparent", "tracestate",
            "cf-ray", "cf-cache-status", "server-timing", "x-runtime", "x-served-by",
            "age", "via", "set-cookie", "keep-alive"
    );

    /**
     * Patterns matching volatile field names in JSON or query params.
     */
    private static final Pattern VOLATILE_KEY_PATTERN = Pattern.compile(
            "(?i)^(csrf.*|.*xsrf.*|.*nonce.*|_?token|authenticity_token|__requestverificationtoken|" +
                    "timestamp|time|created_?at|updated_?at|date|req_?id|request_?id|trace_?id|session_?id)$"
    );

    /**
     * ISO-8601 UTC and offset timestamp regex.
     */
    private static final Pattern ISO8601_PATTERN = Pattern.compile(
            "\\b\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(?:\\.\\d+)?(?:Z|[+-]\\d{2}:?\\d{2})?\\b"
    );

    /**
     * Epoch milliseconds/seconds regex when in numeric context.
     */
    private static final Pattern EPOCH_MILLIS_PATTERN = Pattern.compile(
            "\\b1[5-7]\\d{11}\\b|\\b1[5-7]\\d{8}\\b"
    );

    /**
     * UUID pattern (e.g. 123e4567-e89b-12d3-a456-426614174000).
     */
    private static final Pattern UUID_PATTERN = Pattern.compile(
            "\\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\\b"
    );

    private static final Pattern MULTI_WHITESPACE = Pattern.compile("\\s+");

    public static NormalizedResponse normalize(HttpResponse response) {
        if (response == null) {
            return new NormalizedResponse(0, Collections.emptyMap(), "", null);
        }

        Map<String, List<String>> normalizedHeaders = normalizeHeaders(response.headers());
        String body = response.bodyString();

        JsonNode jsonNode = tryParseJson(body);
        String normalizedBody;

        if (jsonNode != null) {
            JsonNode cleaned = cleanJsonNode(jsonNode);
            normalizedBody = toCanonicalJsonString(cleaned);
            return new NormalizedResponse(response.statusCode(), normalizedHeaders, normalizedBody, cleaned);
        } else {
            normalizedBody = normalizeText(body);
            return new NormalizedResponse(response.statusCode(), normalizedHeaders, normalizedBody, null);
        }
    }

    private static Map<String, List<String>> normalizeHeaders(Map<String, List<String>> headers) {
        Map<String, List<String>> result = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
            String name = entry.getKey().trim().toLowerCase();
            if (!VOLATILE_HEADERS.contains(name)) {
                result.put(name, entry.getValue());
            }
        }
        return Collections.unmodifiableMap(result);
    }

    public static String normalizeText(String text) {
        if (text == null || text.isEmpty()) {
            return "";
        }
        String stripped = ISO8601_PATTERN.matcher(text).replaceAll("<TIMESTAMP>");
        stripped = EPOCH_MILLIS_PATTERN.matcher(stripped).replaceAll("<EPOCH>");
        stripped = MULTI_WHITESPACE.matcher(stripped).replaceAll(" ").trim();
        return stripped;
    }

    private static JsonNode tryParseJson(String body) {
        if (body == null) return null;
        String trimmed = body.trim();
        if ((trimmed.startsWith("{") && trimmed.endsWith("}")) || (trimmed.startsWith("[") && trimmed.endsWith("]"))) {
            try {
                return MAPPER.readTree(trimmed);
            } catch (Exception ignored) {
                return null;
            }
        }
        return null;
    }

    private static JsonNode cleanJsonNode(JsonNode node) {
        if (node.isObject()) {
            ObjectNode obj = (ObjectNode) node;
            List<String> fieldNames = new ArrayList<>();
            obj.fieldNames().forEachRemaining(fieldNames::add);

            for (String fieldName : fieldNames) {
                if (VOLATILE_KEY_PATTERN.matcher(fieldName).matches()) {
                    obj.put(fieldName, "<VOLATILE>");
                } else {
                    JsonNode child = obj.get(fieldName);
                    if (child.isTextual()) {
                        String text = child.asText();
                        if (ISO8601_PATTERN.matcher(text).matches()) {
                            obj.put(fieldName, "<TIMESTAMP>");
                        } else if (UUID_PATTERN.matcher(text).matches() && fieldName.toLowerCase().contains("request")) {
                            obj.put(fieldName, "<UUID>");
                        }
                    } else if (child.isObject() || child.isArray()) {
                        cleanJsonNode(child);
                    }
                }
            }
            return obj;
        } else if (node.isArray()) {
            ArrayNode arr = (ArrayNode) node;
            for (int i = 0; i < arr.size(); i++) {
                JsonNode item = arr.get(i);
                if (item.isObject() || item.isArray()) {
                    cleanJsonNode(item);
                }
            }
            return arr;
        }
        return node;
    }

    public static String toCanonicalJsonString(JsonNode node) {
        if (node == null) return "";
        try {
            Object obj = MAPPER.treeToValue(node, Object.class);
            return MAPPER.writeValueAsString(sortObject(obj));
        } catch (JsonProcessingException e) {
            return node.toString();
        }
    }

    @SuppressWarnings("unchecked")
    private static Object sortObject(Object obj) {
        if (obj instanceof Map) {
            Map<String, Object> map = (Map<String, Object>) obj;
            Map<String, Object> sorted = new TreeMap<>();
            for (Map.Entry<String, Object> entry : map.entrySet()) {
                sorted.put(entry.getKey(), sortObject(entry.getValue()));
            }
            return sorted;
        } else if (obj instanceof List) {
            List<Object> list = (List<Object>) obj;
            List<Object> sortedList = new ArrayList<>(list.size());
            for (Object item : list) {
                sortedList.add(sortObject(item));
            }
            return sortedList;
        }
        return obj;
    }

    /**
     * Normalized response representation containing cleaned body and parsed JSON if applicable.
     */
    public record NormalizedResponse(
            int statusCode,
            Map<String, List<String>> headers,
            String body,
            JsonNode jsonNode
    ) {
        public boolean isJson() {
            return jsonNode != null;
        }
    }
}
