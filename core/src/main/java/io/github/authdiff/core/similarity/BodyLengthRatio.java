package io.github.authdiff.core.similarity;

/**
 * Computes the ratio of shorter to longer body length: min(len1, len2) / max(len1, len2).
 * Returns 1.0 if both bodies are empty, and 0.0 if one is empty and the other is non-empty.
 */
public final class BodyLengthRatio {

    private BodyLengthRatio() {}

    public static double compute(int len1, int len2) {
        if (len1 == 0 && len2 == 0) {
            return 1.0;
        }
        if (len1 <= 0 || len2 <= 0) {
            return 0.0;
        }
        return (double) Math.min(len1, len2) / (double) Math.max(len1, len2);
    }

    public static double compute(String s1, String s2) {
        int l1 = s1 == null ? 0 : s1.length();
        int l2 = s2 == null ? 0 : s2.length();
        return compute(l1, l2);
    }
}
