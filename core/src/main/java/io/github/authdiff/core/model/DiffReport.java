package io.github.authdiff.core.model;

import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Aggregated report of authdiff execution containing all classified findings and summary metrics.
 */
public record DiffReport(
        Instant timestamp,
        int totalRequestsEvaluated,
        List<AuthDiffFinding> findings,
        Map<Verdict, Long> verdictCounts,
        long highConfidenceCount,
        long mediumConfidenceCount,
        long lowConfidenceCount
) {
    public DiffReport {
        findings = findings != null ? Collections.unmodifiableList(findings) : Collections.emptyList();
        verdictCounts = verdictCounts != null ? Collections.unmodifiableMap(verdictCounts) : Collections.emptyMap();
    }

    public static DiffReport fromFindings(List<AuthDiffFinding> findings) {
        Map<Verdict, Long> counts = findings.stream()
                .collect(Collectors.groupingBy(AuthDiffFinding::verdict, Collectors.counting()));

        long high = findings.stream().filter(f -> f.confidence().level() == ConfidenceScore.Level.HIGH).count();
        long med = findings.stream().filter(f -> f.confidence().level() == ConfidenceScore.Level.MEDIUM).count();
        long low = findings.stream().filter(f -> f.confidence().level() == ConfidenceScore.Level.LOW).count();

        return new DiffReport(
                Instant.now(),
                findings.size(),
                findings,
                counts,
                high,
                med,
                low
        );
    }

    public boolean hasVulnerabilitiesAtOrAbove(ConfidenceScore minConfidence) {
        return findings.stream()
                .anyMatch(f -> f.isVulnerability() && f.confidence().value() >= minConfidence.value());
    }
}
