package io.github.authdiff.core.model;

/**
 * Deterministic confidence score from 0 to 100 with categorical bands.
 */
public record ConfidenceScore(int value) implements Comparable<ConfidenceScore> {

    public ConfidenceScore {
        if (value < 0 || value > 100) {
            throw new IllegalArgumentException("Confidence score must be in range [0, 100], got: " + value);
        }
    }

    public enum Level {
        HIGH,
        MEDIUM,
        LOW
    }

    public Level level() {
        if (value >= 75) {
            return Level.HIGH;
        } else if (value >= 40) {
            return Level.MEDIUM;
        } else {
            return Level.LOW;
        }
    }

    public static ConfidenceScore of(int value) {
        return new ConfidenceScore(Math.max(0, Math.min(100, value)));
    }

    @Override
    public int compareTo(ConfidenceScore other) {
        return Integer.compare(this.value, other.value);
    }

    @Override
    public String toString() {
        return value + " (" + level() + ")";
    }
}
