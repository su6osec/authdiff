package io.github.authdiff.burp;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpHeader;
import io.github.authdiff.core.model.HttpRequest;
import io.github.authdiff.core.model.HttpResponse;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.Iterator;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class MontoyaModelConverterTest {

    @Test
    @DisplayName("Converts Montoya HttpRequest to authdiff core HttpRequest accurately")
    void testToCoreRequest() {
        HttpHeader h1 = createHeader("Authorization", "Bearer token-123");
        HttpHeader h2 = createHeader("Accept", "application/json");
        ByteArray body = createByteArray("{\"sample\": true}");

        burp.api.montoya.http.message.requests.HttpRequest mockReq =
                (burp.api.montoya.http.message.requests.HttpRequest) Proxy.newProxyInstance(
                        getClass().getClassLoader(),
                        new Class<?>[]{burp.api.montoya.http.message.requests.HttpRequest.class},
                        (proxy, method, args) -> switch (method.getName()) {
                            case "method" -> "GET";
                            case "url" -> "https://example.com/api/basket/5";
                            case "path" -> "/api/basket/5";
                            case "headers" -> List.of(h1, h2);
                            case "body" -> body;
                            default -> null;
                        }
                );

        HttpRequest coreReq = MontoyaModelConverter.toCoreRequest(mockReq);

        assertThat(coreReq.method()).isEqualTo("GET");
        assertThat(coreReq.url()).isEqualTo("https://example.com/api/basket/5");
        assertThat(coreReq.path()).isEqualTo("/api/basket/5");
        assertThat(coreReq.headerFirstValue("Authorization")).isEqualTo("Bearer token-123");
        assertThat(coreReq.headerFirstValue("Accept")).isEqualTo("application/json");
        assertThat(coreReq.bodyString()).isEqualTo("{\"sample\": true}");
    }

    @Test
    @DisplayName("Converts Montoya HttpResponse to authdiff core HttpResponse accurately")
    void testToCoreResponse() {
        HttpHeader h1 = createHeader("Content-Type", "application/json");
        ByteArray body = createByteArray("{\"id\": 5}");

        burp.api.montoya.http.message.responses.HttpResponse mockRes =
                (burp.api.montoya.http.message.responses.HttpResponse) Proxy.newProxyInstance(
                        getClass().getClassLoader(),
                        new Class<?>[]{burp.api.montoya.http.message.responses.HttpResponse.class},
                        (proxy, method, args) -> switch (method.getName()) {
                            case "statusCode" -> (short) 200;
                            case "headers" -> List.of(h1);
                            case "body" -> body;
                            default -> null;
                        }
                );

        HttpResponse coreRes = MontoyaModelConverter.toCoreResponse(mockRes);

        assertThat(coreRes.statusCode()).isEqualTo(200);
        assertThat(coreRes.headerFirstValue("Content-Type")).isEqualTo("application/json");
        assertThat(coreRes.bodyString()).isEqualTo("{\"id\": 5}");
    }

    private static HttpHeader createHeader(String name, String value) {
        return (HttpHeader) Proxy.newProxyInstance(
                MontoyaModelConverterTest.class.getClassLoader(),
                new Class<?>[]{HttpHeader.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "name" -> name;
                    case "value" -> value;
                    default -> null;
                }
        );
    }

    private static ByteArray createByteArray(String text) {
        byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
        return (ByteArray) Proxy.newProxyInstance(
                MontoyaModelConverterTest.class.getClassLoader(),
                new Class<?>[]{ByteArray.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "getBytes" -> bytes.clone();
                    case "length" -> bytes.length;
                    default -> null;
                }
        );
    }
}
