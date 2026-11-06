package io.github.authdiff.core.model;

/**
 * References an identifier detected in a request (path segment, query param, or JSON field).
 */
public record IdentifierRef(
        Location location,
        String nameOrSegment,
        String value,
        IdentifierType type
) {
    public enum Location {
        PATH,
        QUERY,
        BODY
    }

    public enum IdentifierType {
        NUMERIC,
        UUID,
        HEX_HASH,
        ALPHANUMERIC_KEY
    }

    public String humanReadable() {
        return switch (location) {
            case PATH -> nameOrSegment + "=" + value;
            case QUERY -> nameOrSegment + "=" + value;
            case BODY -> "body." + nameOrSegment + "=" + value;
        };
    }
}
