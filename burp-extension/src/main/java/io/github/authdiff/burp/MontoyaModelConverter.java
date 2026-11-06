package io.github.authdiff.burp;

import burp.api.montoya.http.message.HttpHeader;
import io.github.authdiff.core.model.HttpRequest;
import io.github.authdiff.core.model.HttpResponse;

/**
 * Converts between PortSwigger Montoya HTTP representations and authdiff core domain models.
 */
public final class MontoyaModelConverter {

    private MontoyaModelConverter() {}

    public static HttpRequest toCoreRequest(burp.api.montoya.http.message.requests.HttpRequest burpReq) {
        if (burpReq == null) return null;

        HttpRequest.Builder builder = HttpRequest.builder()
                .method(burpReq.method())
                .url(burpReq.url())
                .path(burpReq.path());

        for (HttpHeader h : burpReq.headers()) {
            builder.header(h.name(), h.value());
        }

        if (burpReq.body() != null) {
            builder.body(burpReq.body().getBytes());
        }

        return builder.build();
    }

    public static HttpResponse toCoreResponse(burp.api.montoya.http.message.responses.HttpResponse burpRes) {
        if (burpRes == null) return null;

        HttpResponse.Builder builder = HttpResponse.builder()
                .statusCode(burpRes.statusCode());

        for (HttpHeader h : burpRes.headers()) {
            builder.header(h.name(), h.value());
        }

        if (burpRes.body() != null) {
            builder.body(burpRes.body().getBytes());
        }

        return builder.build();
    }
}
