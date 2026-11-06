package io.github.authdiff.core.model;

import java.util.Objects;
import java.util.Optional;

/**
 * Represents a complete test exchange:
 * - Owner (Identity A): original captured request and response.
 * - Attacker (Identity B): replayed response using second user credentials.
 * - Anonymous (optional): replayed response without authentication headers/cookies.
 */
public record ExchangePair(
        HttpRequest ownerRequest,
        HttpResponse ownerResponse,
        HttpResponse attackerResponse,
        HttpResponse anonResponse
) {
    public ExchangePair {
        Objects.requireNonNull(ownerRequest, "ownerRequest must not be null");
        Objects.requireNonNull(ownerResponse, "ownerResponse must not be null");
        Objects.requireNonNull(attackerResponse, "attackerResponse must not be null");
    }

    public Optional<HttpResponse> optionalAnonResponse() {
        return Optional.ofNullable(anonResponse);
    }
}
