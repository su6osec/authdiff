package io.github.authdiff.cli.har;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class HarParserTest {

    @Test
    @DisplayName("Parses standard HAR 1.2 entries into HttpRequest and HttpResponse")
    void testParseHar() throws Exception {
        try (InputStream is = getClass().getResourceAsStream("/fixtures/owner.har")) {
            assertThat(is).isNotNull();
            List<HarParser.HarEntry> entries = HarParser.parse(is);

            assertThat(entries).hasSize(3);

            HarParser.HarEntry entry1 = entries.get(0);
            assertThat(entry1.request().method()).isEqualTo("GET");
            assertThat(entry1.request().path()).isEqualTo("/rest/basket/1");
            assertThat(entry1.request().headerFirstValue("Authorization")).isEqualTo("Bearer owner-token-12345");
            assertThat(entry1.response().statusCode()).isEqualTo(200);
            assertThat(entry1.response().bodyString()).contains("\"UserId\":1");
        }
    }
}
