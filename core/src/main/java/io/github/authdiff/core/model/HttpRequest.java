package io.github.authdiff.core.model;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Immutable representation of an HTTP request for analysis and diffing.
 * Independent of any HTTP client or proxy API (Burp, OkHttp, etc.).
 */
public final class HttpRequest {
    private final String method;
    private final String url;
    private final String path;
    private final Map<String, List<String>> headers;
    private final Map<String, String> cookies;
    private final Map<String, List<String>> queryParams;
    private final byte[] body;
    private final String bodyString;

    private HttpRequest(Builder builder) {
        this.method = Objects.requireNonNull(builder.method, "method must not be null").toUpperCase();
        this.url = Objects.requireNonNull(builder.url, "url must not be null");
        this.path = builder.path != null ? builder.path : extractPath(builder.url);
        this.headers = Collections.unmodifiableMap(new LinkedHashMap<>(builder.headers));
        this.cookies = Collections.unmodifiableMap(new LinkedHashMap<>(builder.cookies));
        this.queryParams = Collections.unmodifiableMap(new LinkedHashMap<>(builder.queryParams));
        this.body = builder.body != null ? builder.body.clone() : new byte[0];
        this.bodyString = builder.bodyString != null ? builder.bodyString : new String(this.body);
    }

    public static Builder builder() {
        return new Builder();
    }

    public String method() {
        return method;
    }

    public String url() {
        return url;
    }

    public String path() {
        return path;
    }

    public Map<String, List<String>> headers() {
        return headers;
    }

    public Map<String, String> cookies() {
        return cookies;
    }

    public Map<String, List<String>> queryParams() {
        return queryParams;
    }

    public byte[] body() {
        return body.clone();
    }

    public String bodyString() {
        return bodyString;
    }

    public String headerFirstValue(String name) {
        for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
            if (entry.getKey().equalsIgnoreCase(name) && !entry.getValue().isEmpty()) {
                return entry.getValue().get(0);
            }
        }
        return null;
    }

    private static String extractPath(String rawUrl) {
        try {
            java.net.URI uri = java.net.URI.create(rawUrl);
            String p = uri.getPath();
            return (p == null || p.isEmpty()) ? "/" : p;
        } catch (Exception e) {
            int q = rawUrl.indexOf('?');
            int slash = rawUrl.indexOf('/', rawUrl.indexOf("://") + 3);
            if (slash == -1) return "/";
            return q == -1 ? rawUrl.substring(slash) : rawUrl.substring(slash, q);
        }
    }

    public static final class Builder {
        private String method = "GET";
        private String url = "";
        private String path;
        private final Map<String, List<String>> headers = new LinkedHashMap<>();
        private final Map<String, String> cookies = new LinkedHashMap<>();
        private final Map<String, List<String>> queryParams = new LinkedHashMap<>();
        private byte[] body = new byte[0];
        private String bodyString = "";

        public Builder method(String method) {
            this.method = method;
            return this;
        }

        public Builder url(String url) {
            this.url = url;
            return this;
        }

        public Builder path(String path) {
            this.path = path;
            return this;
        }

        public Builder header(String name, String value) {
            this.headers.computeIfAbsent(name, k -> new java.util.ArrayList<>()).add(value);
            return this;
        }

        public Builder headers(Map<String, List<String>> headers) {
            if (headers != null) {
                this.headers.putAll(headers);
            }
            return this;
        }

        public Builder cookie(String name, String value) {
            this.cookies.put(name, value);
            return this;
        }

        public Builder cookies(Map<String, String> cookies) {
            if (cookies != null) {
                this.cookies.putAll(cookies);
            }
            return this;
        }

        public Builder queryParam(String name, String value) {
            this.queryParams.computeIfAbsent(name, k -> new java.util.ArrayList<>()).add(value);
            return this;
        }

        public Builder queryParams(Map<String, List<String>> params) {
            if (params != null) {
                this.queryParams.putAll(params);
            }
            return this;
        }

        public Builder body(byte[] body) {
            if (body != null) {
                this.body = body.clone();
                this.bodyString = new String(body);
            }
            return this;
        }

        public Builder body(String bodyString) {
            if (bodyString != null) {
                this.bodyString = bodyString;
                this.body = bodyString.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            }
            return this;
        }

        public HttpRequest build() {
            return new HttpRequest(this);
        }
    }
}
