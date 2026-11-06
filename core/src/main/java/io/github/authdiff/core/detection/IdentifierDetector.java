package io.github.authdiff.core.detection;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.authdiff.core.model.HttpRequest;
import io.github.authdiff.core.model.IdentifierRef;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Detects object-level identifiers in request path, query parameters, and JSON body.
 */
public final class IdentifierDetector {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final Pattern NUMERIC_ID = Pattern.compile("^\\d{1,10}$");
    private static final Pattern UUID_PATTERN = Pattern.compile(
            "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
    );
    private static final Pattern HEX_HASH_PATTERN = Pattern.compile("^[0-9a-fA-F]{16,64}$");

    private static final Pattern ID_PARAM_NAME = Pattern.compile(
            "(?i)^.*(id|uuid|account|basket|cart|order|user|doc|item|profile|invoice|record|msg|message|file).*$"
    );

    private IdentifierDetector() {}

    public static List<IdentifierRef> detect(HttpRequest request) {
        if (request == null) {
            return Collections.emptyList();
        }

        List<IdentifierRef> results = new ArrayList<>();
        detectPathIdentifiers(request.path(), results);
        detectQueryIdentifiers(request.queryParams(), results);
        detectBodyIdentifiers(request.bodyString(), results);

        return Collections.unmodifiableList(results);
    }

    private static void detectPathIdentifiers(String path, List<IdentifierRef> results) {
        if (path == null || path.isEmpty()) return;
        String[] segments = path.split("/");
        for (int i = 0; i < segments.length; i++) {
            String seg = segments[i].trim();
            if (seg.isEmpty()) continue;

            String contextName = (i > 0 && !segments[i - 1].isEmpty()) ? segments[i - 1] : "segment[" + i + "]";

            if (UUID_PATTERN.matcher(seg).matches()) {
                results.add(new IdentifierRef(IdentifierRef.Location.PATH, contextName, seg, IdentifierRef.IdentifierType.UUID));
            } else if (NUMERIC_ID.matcher(seg).matches()) {
                results.add(new IdentifierRef(IdentifierRef.Location.PATH, contextName, seg, IdentifierRef.IdentifierType.NUMERIC));
            } else if (HEX_HASH_PATTERN.matcher(seg).matches()) {
                results.add(new IdentifierRef(IdentifierRef.Location.PATH, contextName, seg, IdentifierRef.IdentifierType.HEX_HASH));
            }
        }
    }

    private static void detectQueryIdentifiers(Map<String, List<String>> queryParams, List<IdentifierRef> results) {
        if (queryParams == null) return;
        for (Map.Entry<String, List<String>> entry : queryParams.entrySet()) {
            String name = entry.getKey();
            for (String val : entry.getValue()) {
                if (val == null || val.isBlank()) continue;
                String v = val.trim();

                if (UUID_PATTERN.matcher(v).matches()) {
                    results.add(new IdentifierRef(IdentifierRef.Location.QUERY, name, v, IdentifierRef.IdentifierType.UUID));
                } else if (NUMERIC_ID.matcher(v).matches() && ID_PARAM_NAME.matcher(name).matches()) {
                    results.add(new IdentifierRef(IdentifierRef.Location.QUERY, name, v, IdentifierRef.IdentifierType.NUMERIC));
                } else if (HEX_HASH_PATTERN.matcher(v).matches() && ID_PARAM_NAME.matcher(name).matches()) {
                    results.add(new IdentifierRef(IdentifierRef.Location.QUERY, name, v, IdentifierRef.IdentifierType.HEX_HASH));
                }
            }
        }
    }

    private static void detectBodyIdentifiers(String body, List<IdentifierRef> results) {
        if (body == null || body.isBlank()) return;
        try {
            JsonNode root = MAPPER.readTree(body);
            if (root.isObject()) {
                Iterator<Map.Entry<String, JsonNode>> fields = root.fields();
                while (fields.hasNext()) {
                    Map.Entry<String, JsonNode> field = fields.next();
                    String key = field.getKey();
                    JsonNode valNode = field.getValue();

                    if (valNode.isNumber() && ID_PARAM_NAME.matcher(key).matches()) {
                        results.add(new IdentifierRef(IdentifierRef.Location.BODY, key, valNode.asText(), IdentifierRef.IdentifierType.NUMERIC));
                    } else if (valNode.isTextual()) {
                        String text = valNode.asText().trim();
                        if (UUID_PATTERN.matcher(text).matches()) {
                            results.add(new IdentifierRef(IdentifierRef.Location.BODY, key, text, IdentifierRef.IdentifierType.UUID));
                        } else if (NUMERIC_ID.matcher(text).matches() && ID_PARAM_NAME.matcher(key).matches()) {
                            results.add(new IdentifierRef(IdentifierRef.Location.BODY, key, text, IdentifierRef.IdentifierType.NUMERIC));
                        }
                    }
                }
            }
        } catch (Exception ignored) {
            // Not a JSON body, ignore
        }
    }
}
