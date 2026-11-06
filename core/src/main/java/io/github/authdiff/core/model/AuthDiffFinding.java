package io.github.authdiff.core.model;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * A classified finding for an endpoint, with full deterministic evidence and explainability.
 */
public record AuthDiffFinding(
        String id,
        String method,
        String url,
        String path,
        List<IdentifierRef> detectedIdentifiers,
        Verdict verdict,
        ConfidenceScore confidence,
        List<FindingSignal> signals,
        int ownerStatusCode,
        int attackerStatusCode,
        Optional<Integer> anonStatusCode,
        double attackerSimilarity,
        Optional<Double> anonSimilarity,
        double attackerLengthRatio,
        String humanSummary
) {
    public AuthDiffFinding {
        detectedIdentifiers = detectedIdentifiers != null
                ? Collections.unmodifiableList(detectedIdentifiers)
                : Collections.emptyList();
        signals = signals != null
                ? Collections.unmodifiableList(signals)
                : Collections.emptyList();
    }

    public boolean isVulnerability() {
        return verdict.isVulnerability();
    }

    public String primaryIdentifierString() {
        if (detectedIdentifiers.isEmpty()) {
            return "none";
        }
        return detectedIdentifiers.get(0).humanReadable();
    }
}
