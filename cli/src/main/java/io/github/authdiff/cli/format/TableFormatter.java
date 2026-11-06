package io.github.authdiff.cli.format;

import io.github.authdiff.core.model.AuthDiffFinding;
import io.github.authdiff.core.model.ConfidenceScore;
import io.github.authdiff.core.model.DiffReport;
import io.github.authdiff.core.model.Verdict;

/**
 * Renders an ASCII table for terminal output with color-coded verdicts.
 */
public final class TableFormatter {

    // ANSI Colors
    private static final String RESET = "\u001B[0m";
    private static final String RED = "\u001B[31m";
    private static final String GREEN = "\u001B[32m";
    private static final String YELLOW = "\u001B[33m";
    private static final String CYAN = "\u001B[36m";
    private static final String BOLD = "\u001B[1m";

    private TableFormatter() {}

    public static String format(DiffReport report, boolean useColors) {
        StringBuilder sb = new StringBuilder();

        sb.append("\n");
        sb.append(BOLD).append("================================ authdiff Report ================================").append(RESET).append("\n");
        sb.append(String.format("Evaluated %d request(s) at %s%n%n", report.totalRequestsEvaluated(), report.timestamp()));

        String headerFmt = "%-7s %-32s %-16s %-12s %-10s %-24s %-10s%n";
        String rowFmt = "%-7s %-32s %-16s %-12s %-10s %-24s %-10s%n";

        sb.append(String.format(headerFmt, "METHOD", "PATH", "OBJECT-ID", "STATUS (A/B/?)", "SIM (B)", "VERDICT", "CONFIDENCE"));
        sb.append("--------------------------------------------------------------------------------------------------------------------\n");

        for (AuthDiffFinding f : report.findings()) {
            String path = truncate(f.path(), 32);
            String objId = truncate(f.primaryIdentifierString(), 16);
            String anonStr = f.anonStatusCode().map(String::valueOf).orElse("-");
            String status = String.format("%d / %d / %s", f.ownerStatusCode(), f.attackerStatusCode(), anonStr);
            String sim = String.format("%.1f%%", f.attackerSimilarity() * 100.0);
            String verdictStr = colorizeVerdict(f.verdict(), useColors);
            String confStr = colorizeConfidence(f.confidence(), useColors);

            sb.append(String.format(rowFmt, f.method(), path, objId, status, sim, verdictStr, confStr));
        }

        sb.append("--------------------------------------------------------------------------------------------------------------------\n");
        sb.append(BOLD).append("Summary: ").append(RESET);
        sb.append(String.format("Total: %d | IDOR/BOLA: %d | Missing Auth: %d | Enforced: %d | Inconclusive: %d%n",
                report.totalRequestsEvaluated(),
                report.verdictCounts().getOrDefault(Verdict.LIKELY_IDOR_BOLA, 0L),
                report.verdictCounts().getOrDefault(Verdict.MISSING_AUTHENTICATION, 0L),
                report.verdictCounts().getOrDefault(Verdict.ENFORCED, 0L),
                report.verdictCounts().getOrDefault(Verdict.INCONCLUSIVE, 0L)
        ));
        sb.append(String.format("Confidence Levels: High: %d | Medium: %d | Low: %d%n%n",
                report.highConfidenceCount(), report.mediumConfidenceCount(), report.lowConfidenceCount()));

        return sb.toString();
    }

    private static String colorizeVerdict(Verdict v, boolean colors) {
        if (!colors) return v.name();
        return switch (v) {
            case LIKELY_IDOR_BOLA -> RED + BOLD + v.name() + RESET;
            case MISSING_AUTHENTICATION -> RED + v.name() + RESET;
            case ENFORCED -> GREEN + v.name() + RESET;
            case INCONCLUSIVE -> YELLOW + v.name() + RESET;
        };
    }

    private static String colorizeConfidence(ConfidenceScore score, boolean colors) {
        String text = score.value() + "%";
        if (!colors) return text;
        return switch (score.level()) {
            case HIGH -> RED + text + RESET;
            case MEDIUM -> YELLOW + text + RESET;
            case LOW -> CYAN + text + RESET;
        };
    }

    private static String truncate(String text, int max) {
        if (text == null) return "";
        if (text.length() <= max) return text;
        return text.substring(0, max - 3) + "...";
    }
}
