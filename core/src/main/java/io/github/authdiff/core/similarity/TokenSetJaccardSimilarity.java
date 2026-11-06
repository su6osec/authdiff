package io.github.authdiff.core.similarity;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Computes token-set Jaccard similarity between two strings.
 * <p>
 * Design Choice:
 * Token-set Jaccard index is used instead of Levenshtein/edit-distance because:
 * 1. Complexity: Operates in O(N + M) time and memory, whereas edit distance is O(N * M),
 *    which causes severe performance degradation or OutOfMemory errors on typical HTTP bodies (>50KB).
 * 2. Structure-agnostic: Naturally accounts for harmless token order permutations without penalizing similarity.
 * 3. Determinism: Strictly bounded between 0.0 and 1.0.
 */
public final class TokenSetJaccardSimilarity {

    private static final Pattern TOKEN_SPLIT = Pattern.compile("[^a-zA-Z0-9_]+");

    private TokenSetJaccardSimilarity() {}

    public static double compute(String s1, String s2) {
        if (s1 == null) s1 = "";
        if (s2 == null) s2 = "";

        if (s1.equals(s2)) {
            return 1.0;
        }

        Set<String> tokens1 = tokenize(s1);
        Set<String> tokens2 = tokenize(s2);

        if (tokens1.isEmpty() && tokens2.isEmpty()) {
            return 1.0;
        }
        if (tokens1.isEmpty() || tokens2.isEmpty()) {
            return 0.0;
        }

        Set<String> intersection = new HashSet<>(tokens1);
        intersection.retainAll(tokens2);

        Set<String> union = new HashSet<>(tokens1);
        union.addAll(tokens2);

        return (double) intersection.size() / (double) union.size();
    }

    public static Set<String> tokenize(String input) {
        if (input == null || input.isBlank()) {
            return Collections.emptySet();
        }
        String[] parts = TOKEN_SPLIT.split(input.toLowerCase());
        Set<String> tokens = new HashSet<>();
        for (String p : parts) {
            if (!p.isBlank()) {
                tokens.add(p);
            }
        }
        return tokens;
    }
}
