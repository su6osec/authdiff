package io.github.authdiff.core.model;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Immutable representation of an HTTP response for analysis and diffing.
 */
public final class HttpResponse {
    private final int statusCode;
    private final Map<String, List<String>> headers;
    private final Map<String, String> cookies;
    private final byte[] body;
    private final String bodyString;
    private final long responseTimeMs;

    private HttpResponse(Builder builder) {
        this.statusCode = builder.statusCode;
        this.headers = Collections.unmodifiableMap(new LinkedHashMap<>(builder.headers));
        this.cookies = Collections.unmodifiableMap(new LinkedHashMap<>(builder.cookies));
        this.body = builder.body != null ? builder.body.clone() : new byte[0];
        this.bodyString = builder.bodyString != null ? builder.bodyString : new String(this.body);
        this.responseTimeMs = builder.responseTimeMs;
    }

    public static Builder builder() {
        return new Builder();
    }

    public int statusCode() {
        return statusCode;
    }

    public Map<String, List<String>> headers() {
        return headers;
    }

    public Map<String, String> cookies() {
        return cookies;
    }

    public byte[] body() {
        return body.clone();
    }

    public String bodyString() {
        return bodyString;
    }

    public long responseTimeMs() {
        return responseTimeMs;
    }

    public String headerFirstValue(String name) {
        for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
            if (entry.getKey().equalsIgnoreCase(name) && !entry.getValue().isEmpty()) {
                return entry.getValue().get(0);
            }
        }
        return null;
    }

    public boolean isSuccess() {
        return statusCode >= 200 && statusCode < 300;
    }

    public boolean isRedirect() {
        return statusCode >= 300 && statusCode < 400;
    }

    public boolean isClientError() {
        return statusCode >= 400 && statusCode < 500;
    }

    public boolean isAccessDenied() {
        return statusCode == 401 || statusCode == 403;
    }

    public static final class Builder {
        private int statusCode = 200;
        private final Map<String, List<String>> headers = new LinkedHashMap<>();
        private final Map<String, String> cookies = new LinkedHashMap<>();
        private byte[] body = new byte[0];
        private String bodyString = "";
        private long responseTimeMs = 0;

        public Builder statusCode(int statusCode) {
            this.statusCode = statusCode;
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

        public Builder responseTimeMs(long ms) {
            this.responseTimeMs = ms;
            return this;
        }

        public HttpResponse build() {
            return new HttpResponse(this);
        }
    }
}
