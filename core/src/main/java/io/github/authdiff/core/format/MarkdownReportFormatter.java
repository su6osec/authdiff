package io.github.authdiff.core.format;

import io.github.authdiff.core.model.AuthDiffFinding;
import io.github.authdiff.core.model.DiffReport;
import io.github.authdiff.core.model.FindingSignal;
import io.github.authdiff.core.model.Verdict;

/**
 * Formats DiffReport as GitHub-flavored Markdown.
 */
public final class MarkdownReportFormatter {

    private MarkdownReportFormatter() {}

    public static String format(DiffReport report) {
        StringBuilder sb = new StringBuilder();

        sb.append("# authdiff Security Assessment Report\n\n");
        sb.append("**Timestamp:** ").append(report.timestamp()).append("  \n");
        sb.append("**Total Endpoints Evaluated:** ").append(report.totalRequestsEvaluated()).append("\n\n");

        sb.append("## Executive Summary\n\n");
        sb.append("| Verdict | Count |\n");
        sb.append("| :--- | :--- |\n");
        sb.append("| **Likely IDOR / BOLA** | ").append(report.verdictCounts().getOrDefault(Verdict.LIKELY_IDOR_BOLA, 0L)).append(" |\n");
        sb.append("| **Missing Authentication** | ").append(report.verdictCounts().getOrDefault(Verdict.MISSING_AUTHENTICATION, 0L)).append(" |\n");
        sb.append("| **Access Control Enforced** | ").append(report.verdictCounts().getOrDefault(Verdict.ENFORCED, 0L)).append(" |\n");
        sb.append("| **Inconclusive** | ").append(report.verdictCounts().getOrDefault(Verdict.INCONCLUSIVE, 0L)).append(" |\n\n");

        sb.append("## Findings Table\n\n");
        sb.append("| Method | Path | Object ID | Status (A / B / Anon) | Attacker Similarity | Verdict | Confidence |\n");
        sb.append("| :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n");

        for (AuthDiffFinding f : report.findings()) {
            String anonStr = f.anonStatusCode().map(String::valueOf).orElse("-");
            String status = String.format("%d / %d / %s", f.ownerStatusCode(), f.attackerStatusCode(), anonStr);
            String sim = String.format("%.1f%%", f.attackerSimilarity() * 100.0);
            sb.append(String.format("| `%s` | `%s` | `%s` | `%s` | %s | **%s** | %d%% (%s) |\n",
                    f.method(), f.path(), f.primaryIdentifierString(), status, sim,
                    f.verdict().displayName(), f.confidence().value(), f.confidence().level()));
        }

        sb.append("\n## Detailed Findings Breakdown\n\n");
        for (AuthDiffFinding f : report.findings()) {
            sb.append("### `").append(f.method()).append(" ").append(f.path()).append("`\n\n");
            sb.append("- **Verdict:** ").append(f.verdict().displayName()).append("\n");
            sb.append("- **Confidence:** ").append(f.confidence().value()).append("% (").append(f.confidence().level()).append(")\n");
            sb.append("- **Summary:** ").append(f.humanSummary()).append("\n");
            sb.append("- **Signals & Evidence:**\n");
            for (FindingSignal signal : f.signals()) {
                sb.append("  - `[").append(signal.category()).append("]`: ").append(signal.description()).append("\n");
            }
            sb.append("\n");
        }

        return sb.toString();
    }
}
