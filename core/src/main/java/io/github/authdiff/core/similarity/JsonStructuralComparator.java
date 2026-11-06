package io.github.authdiff.core.similarity;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

/**
 * Structural JSON comparator that analyzes key-set overlap and shared-value overlap
 * between two JSON trees.
 */
public final class JsonStructuralComparator {

    private JsonStructuralComparator() {}

    public record ComparisonResult(
            double keySetOverlap,
            double valueOverlap,
            double compositeSimilarity,
            Set<String> sharedKeys,
            Set<String> uniqueToA,
            Set<String> uniqueToB
    ) {}

    public static ComparisonResult compare(JsonNode nodeA, JsonNode nodeB) {
        if (nodeA == null && nodeB == null) {
            return new ComparisonResult(1.0, 1.0, 1.0, Collections.emptySet(), Collections.emptySet(), Collections.emptySet());
        }
        if (nodeA == null || nodeB == null) {
            return new ComparisonResult(0.0, 0.0, 0.0, Collections.emptySet(), Collections.emptySet(), Collections.emptySet());
        }

        Map<String, String> flatA = new HashMap<>();
        Map<String, String> flatB = new HashMap<>();

        flatten("", nodeA, flatA);
        flatten("", nodeB, flatB);

        Set<String> keysA = flatA.keySet();
        Set<String> keysB = flatB.keySet();

        if (keysA.isEmpty() && keysB.isEmpty()) {
            return new ComparisonResult(1.0, 1.0, 1.0, Collections.emptySet(), Collections.emptySet(), Collections.emptySet());
        }
        if (keysA.isEmpty() || keysB.isEmpty()) {
            return new ComparisonResult(0.0, 0.0, 0.0, Collections.emptySet(), keysA, keysB);
        }

        Set<String> sharedKeys = new HashSet<>(keysA);
        sharedKeys.retainAll(keysB);

        Set<String> unionKeys = new HashSet<>(keysA);
        unionKeys.addAll(keysB);

        double keyOverlap = (double) sharedKeys.size() / (double) unionKeys.size();

        int matchingValues = 0;
        for (String key : sharedKeys) {
            String valA = flatA.get(key);
            String valB = flatB.get(key);
            if (valA != null && valA.equals(valB)) {
                matchingValues++;
            }
        }

        double valueOverlap = sharedKeys.isEmpty() ? 0.0 : (double) matchingValues / (double) sharedKeys.size();

        // Composite similarity: 40% weight on schema structure (keys), 60% on shared value content
        double composite = (0.4 * keyOverlap) + (0.6 * valueOverlap);

        Set<String> uniqueA = new HashSet<>(keysA);
        uniqueA.removeAll(keysB);

        Set<String> uniqueB = new HashSet<>(keysB);
        uniqueB.removeAll(keysA);

        return new ComparisonResult(keyOverlap, valueOverlap, composite, sharedKeys, uniqueA, uniqueB);
    }

    private static void flatten(String prefix, JsonNode node, Map<String, String> target) {
        if (node.isObject()) {
            Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> field = fields.next();
                String nextPrefix = prefix.isEmpty() ? field.getKey() : prefix + "." + field.getKey();
                flatten(nextPrefix, field.getValue(), target);
            }
        } else if (node.isArray()) {
            for (int i = 0; i < node.size(); i++) {
                String nextPrefix = prefix + "[" + i + "]";
                flatten(nextPrefix, node.get(i), target);
            }
        } else {
            target.put(prefix, node.asText());
        }
    }
}
