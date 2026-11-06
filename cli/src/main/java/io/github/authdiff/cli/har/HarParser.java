package io.github.authdiff.cli.har;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.authdiff.core.model.HttpRequest;
import io.github.authdiff.core.model.HttpResponse;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

/**
 * Parses HTTP Archive (HAR 1.2) files into core HttpRequest and HttpResponse domain models.
 */
public final class HarParser {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    public record HarEntry(HttpRequest request, HttpResponse response) {}

    public static List<HarEntry> parse(File harFile) throws IOException {
        if (harFile == null || !harFile.exists()) {
            throw new IllegalArgumentException("HAR file does not exist: " + harFile);
        }
        JsonNode root = MAPPER.readTree(harFile);
        return parseRoot(root);
    }

    public static List<HarEntry> parse(InputStream inputStream) throws IOException {
        JsonNode root = MAPPER.readTree(inputStream);
        return parseRoot(root);
    }

    public static List<HarEntry> parse(String jsonContent) throws IOException {
        JsonNode root = MAPPER.readTree(jsonContent);
        return parseRoot(root);
    }

    private static List<HarEntry> parseRoot(JsonNode root) {
        JsonNode entriesNode = root.path("log").path("entries");
        if (!entriesNode.isArray()) {
            return Collections.emptyList();
        }

        List<HarEntry> entries = new ArrayList<>();
        for (JsonNode entryNode : entriesNode) {
            HttpRequest req = parseRequest(entryNode.path("request"));
            HttpResponse res = parseResponse(entryNode.path("response"));
            if (req != null && res != null) {
                entries.add(new HarEntry(req, res));
            }
        }
        return Collections.unmodifiableList(entries);
    }

    private static HttpRequest parseRequest(JsonNode reqNode) {
        if (reqNode.isMissingNode() || reqNode.isNull()) {
            return null;
        }

        HttpRequest.Builder builder = HttpRequest.builder();
        builder.method(reqNode.path("method").asText("GET"));
        builder.url(reqNode.path("url").asText(""));

        // Headers
        JsonNode headersNode = reqNode.path("headers");
        if (headersNode.isArray()) {
            for (JsonNode h : headersNode) {
                String name = h.path("name").asText();
                String value = h.path("value").asText();
                if (!name.isBlank()) {
                    builder.header(name, value);
                }
            }
        }

        // Cookies
        JsonNode cookiesNode = reqNode.path("cookies");
        if (cookiesNode.isArray()) {
            for (JsonNode c : cookiesNode) {
                String name = c.path("name").asText();
                String value = c.path("value").asText();
                if (!name.isBlank()) {
                    builder.cookie(name, value);
                }
            }
        }

        // Query string
        JsonNode queryNode = reqNode.path("queryString");
        if (queryNode.isArray()) {
            for (JsonNode q : queryNode) {
                String name = q.path("name").asText();
                String value = q.path("value").asText();
                if (!name.isBlank()) {
                    builder.queryParam(name, value);
                }
            }
        }

        // Post Data / Body
        JsonNode postDataNode = reqNode.path("postData");
        if (!postDataNode.isMissingNode()) {
            String text = postDataNode.path("text").asText("");
            builder.body(text);
        }

        return builder.build();
    }

    private static HttpResponse parseResponse(JsonNode resNode) {
        if (resNode.isMissingNode() || resNode.isNull()) {
            return null;
        }

        HttpResponse.Builder builder = HttpResponse.builder();
        builder.statusCode(resNode.path("status").asInt(200));

        // Headers
        JsonNode headersNode = resNode.path("headers");
        if (headersNode.isArray()) {
            for (JsonNode h : headersNode) {
                String name = h.path("name").asText();
                String value = h.path("value").asText();
                if (!name.isBlank()) {
                    builder.header(name, value);
                }
            }
        }

        // Cookies
        JsonNode cookiesNode = resNode.path("cookies");
        if (cookiesNode.isArray()) {
            for (JsonNode c : cookiesNode) {
                String name = c.path("name").asText();
                String value = c.path("value").asText();
                if (!name.isBlank()) {
                    builder.cookie(name, value);
                }
            }
        }

        // Content / Body
        JsonNode contentNode = resNode.path("content");
        if (!contentNode.isMissingNode()) {
            String text = contentNode.path("text").asText("");
            String encoding = contentNode.path("encoding").asText("");
            if ("base64".equalsIgnoreCase(encoding)) {
                try {
                    byte[] decoded = Base64.getDecoder().decode(text);
                    builder.body(decoded);
                } catch (Exception e) {
                    builder.body(text.getBytes(StandardCharsets.UTF_8));
                }
            } else {
                builder.body(text);
            }
        }

        return builder.build();
    }
}
