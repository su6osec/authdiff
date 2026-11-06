package io.github.authdiff.burp.model;

import burp.api.montoya.http.message.HttpRequestResponse;
import io.github.authdiff.core.model.AuthDiffFinding;

/**
 * Stores a classified finding along with the original Montoya HTTP request/response objects
 * for display in Burp's native message viewers.
 */
public record BurpExchangeRecord(
        int index,
        AuthDiffFinding finding,
        HttpRequestResponse ownerExchange,
        HttpRequestResponse attackerExchange,
        HttpRequestResponse anonExchange
) {}
