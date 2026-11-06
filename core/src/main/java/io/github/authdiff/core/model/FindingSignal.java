package io.github.authdiff.core.model;

/**
 * A discrete, explainable signal contributing to the classification verdict.
 */
public record FindingSignal(
        SignalCategory category,
        String code,
        String description,
        int weightDelta
) {
    public enum SignalCategory {
        STATUS_CODE,
        OBJECT_IDENTIFIER,
        BODY_SIMILARITY,
        JSON_STRUCTURE,
        TRAP_DETECTION,
        ALLOWLIST,
        ANONYMOUS_BEHAVIOR
    }

    public static FindingSignal of(SignalCategory category, String code, String description, int weightDelta) {
        return new FindingSignal(category, code, description, weightDelta);
    }
}
