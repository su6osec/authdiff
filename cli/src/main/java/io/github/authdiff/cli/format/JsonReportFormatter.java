package io.github.authdiff.cli.format;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.github.authdiff.core.model.DiffReport;

import java.io.IOException;

/**
 * Formats DiffReport into standardized JSON output.
 */
public final class JsonReportFormatter {

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .registerModule(new JavaTimeModule())
            .registerModule(new Jdk8Module())
            .enable(SerializationFeature.INDENT_OUTPUT)
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
            .setSerializationInclusion(JsonInclude.Include.NON_NULL);

    private JsonReportFormatter() {}

    public static String format(DiffReport report) throws IOException {
        return MAPPER.writeValueAsString(report);
    }
}
