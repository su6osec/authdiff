package io.github.authdiff.cli;

import io.github.authdiff.cli.format.JsonReportFormatter;
import io.github.authdiff.cli.format.MarkdownReportFormatter;
import io.github.authdiff.cli.format.TableFormatter;
import io.github.authdiff.cli.har.HarMatcher;
import io.github.authdiff.cli.har.HarParser;
import io.github.authdiff.core.detection.AuthDiffClassifier;
import io.github.authdiff.core.model.AuthDiffFinding;
import io.github.authdiff.core.model.ConfidenceScore;
import io.github.authdiff.core.model.DiffReport;
import io.github.authdiff.core.model.ExchangePair;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;

@Command(
        name = "compare",
        description = "Performs offline comparison of HAR captures recorded under different user sessions (no network required)."
)
public final class CompareCommand implements Callable<Integer> {

    @Option(names = {"--a", "--owner"}, required = true, description = "Path to owner (Identity A) HAR capture file")
    private File ownerHar;

    @Option(names = {"--b", "--attacker"}, required = true, description = "Path to secondary user (Identity B) HAR capture file")
    private File attackerHar;

    @Option(names = {"--anon", "--anonymous"}, description = "Optional path to unauthenticated (Anon) HAR capture file")
    private File anonHar;

    @Option(names = {"--allowlist"}, description = "Comma-separated path globs to treat as public endpoints (e.g. /api/public/**)")
    private String allowlist;

    @Option(names = {"--format"}, defaultValue = "TABLE", description = "Output format: TABLE, JSON, or MARKDOWN")
    private String format = "TABLE";

    @Option(names = {"--out", "-o"}, description = "Optional output file path to write report to")
    private File outputFile;

    @Option(names = {"--fail-on"}, defaultValue = "MEDIUM", description = "Exit with code 1 if findings at or above level are present: HIGH, MEDIUM, LOW, or NONE")
    private String failOn = "MEDIUM";

    @Option(names = {"--no-color"}, description = "Disable ANSI terminal color output")
    private boolean noColor = false;

    @Override
    public Integer call() throws Exception {
        if (!ownerHar.exists()) {
            System.err.println("[!] Owner HAR file not found: " + ownerHar.getAbsolutePath());
            return 2;
        }
        if (!attackerHar.exists()) {
            System.err.println("[!] Attacker HAR file not found: " + attackerHar.getAbsolutePath());
            return 2;
        }

        List<HarParser.HarEntry> ownerEntries = HarParser.parse(ownerHar);
        List<HarParser.HarEntry> attackerEntries = HarParser.parse(attackerHar);
        List<HarParser.HarEntry> anonEntries = (anonHar != null && anonHar.exists())
                ? HarParser.parse(anonHar)
                : List.of();

        List<ExchangePair> matchedPairs = HarMatcher.correlate(ownerEntries, attackerEntries, anonEntries);

        if (matchedPairs.isEmpty()) {
            System.err.println("[!] No matching endpoint exchanges found between the provided HAR files.");
            return 0;
        }

        List<String> allowlistGlobs = new ArrayList<>();
        if (allowlist != null && !allowlist.isBlank()) {
            for (String g : allowlist.split(",")) {
                if (!g.isBlank()) allowlistGlobs.add(g.trim());
            }
        }

        AuthDiffClassifier classifier = new AuthDiffClassifier(
                new AuthDiffClassifier.Options(allowlistGlobs, 0.70, 0.85)
        );

        List<AuthDiffFinding> findings = new ArrayList<>();
        for (ExchangePair pair : matchedPairs) {
            findings.add(classifier.classify(pair));
        }

        DiffReport report = DiffReport.fromFindings(findings);
        String formattedOutput = switch (format.toUpperCase()) {
            case "JSON" -> JsonReportFormatter.format(report);
            case "MARKDOWN", "MD" -> MarkdownReportFormatter.format(report);
            default -> TableFormatter.format(report, !noColor);
        };

        if (outputFile != null) {
            Files.writeString(outputFile.toPath(), formattedOutput);
            System.out.println("[+] Report successfully saved to: " + outputFile.getAbsolutePath());
        } else {
            System.out.println(formattedOutput);
        }

        return evaluateExitCode(report);
    }

    private int evaluateExitCode(DiffReport report) {
        if ("NONE".equalsIgnoreCase(failOn)) {
            return 0;
        }

        ConfidenceScore.Level targetLevel = switch (failOn.toUpperCase()) {
            case "HIGH" -> ConfidenceScore.Level.HIGH;
            case "LOW" -> ConfidenceScore.Level.LOW;
            default -> ConfidenceScore.Level.MEDIUM;
        };

        boolean hasFailing = report.findings().stream().anyMatch(f -> {
            if (!f.isVulnerability()) return false;
            return switch (targetLevel) {
                case HIGH -> f.confidence().level() == ConfidenceScore.Level.HIGH;
                case MEDIUM -> f.confidence().level() == ConfidenceScore.Level.HIGH || f.confidence().level() == ConfidenceScore.Level.MEDIUM;
                case LOW -> true;
            };
        });

        return hasFailing ? 1 : 0;
    }
}
