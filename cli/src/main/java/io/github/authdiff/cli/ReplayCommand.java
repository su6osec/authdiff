package io.github.authdiff.cli;

import io.github.authdiff.cli.format.JsonReportFormatter;
import io.github.authdiff.cli.format.MarkdownReportFormatter;
import io.github.authdiff.cli.format.TableFormatter;
import io.github.authdiff.cli.har.HarParser;
import io.github.authdiff.cli.replay.HttpReplayer;
import io.github.authdiff.core.detection.AuthDiffClassifier;
import io.github.authdiff.core.model.AuthDiffFinding;
import io.github.authdiff.core.model.ConfidenceScore;
import io.github.authdiff.core.model.DiffReport;
import io.github.authdiff.core.model.ExchangePair;
import io.github.authdiff.core.model.HttpRequest;
import io.github.authdiff.core.model.HttpResponse;
import io.github.authdiff.core.redact.CredentialRedactor;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.io.File;
import java.nio.file.Files;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;

@Command(
        name = "replay",
        description = "Replays owner's captured requests with attacker credentials and anonymous identity against live target scope."
)
public final class ReplayCommand implements Callable<Integer> {

    @Option(names = {"--har"}, required = true, description = "Path to owner HAR file containing baseline requests")
    private File harFile;

    @Option(names = {"--scope"}, required = true, description = "Target host scope (e.g. localhost, juice.local). Requests outside scope will be refused.")
    private String scope;

    @Option(names = {"--attacker-header", "-H"}, description = "Header(s) to apply for User B (e.g. 'Authorization: Bearer token-b', 'Cookie: session=b')")
    private List<String> attackerHeaders = new ArrayList<>();

    @Option(names = {"--allow-unsafe-methods"}, description = "Explicitly permit state-changing HTTP methods (POST, PUT, PATCH, DELETE). By default only GET, HEAD, OPTIONS are replayed.")
    private boolean allowUnsafeMethods = false;

    @Option(names = {"--rate-limit"}, defaultValue = "2.0", description = "Target request rate limit in requests/second (default: 2.0 req/s)")
    private double rateLimit = 2.0;

    @Option(names = {"--max-requests"}, defaultValue = "500", description = "Hard safety cap on total HTTP replays per run (default: 500)")
    private int maxRequests = 500;

    @Option(names = {"--no-anon"}, description = "Disable testing unauthenticated (anonymous) requests")
    private boolean noAnon = false;

    @Option(names = {"--include-credentials"}, description = "Do not redact Authorization headers and cookies in exported reports (credentials redacted by default)")
    private boolean includeCredentials = false;

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
        if (!harFile.exists()) {
            System.err.println("[!] HAR file not found: " + harFile.getAbsolutePath());
            return 2;
        }

        Set<String> scopeHosts = new HashSet<>();
        for (String s : scope.split(",")) {
            if (!s.isBlank()) {
                scopeHosts.add(s.trim());
            }
        }

        if (scopeHosts.isEmpty()) {
            System.err.println("[!] Scope hosts list cannot be empty. Refusing replay.");
            return 2;
        }

        Map<String, String> parsedAttackerHeaders = new HashMap<>();
        for (String h : attackerHeaders) {
            int colon = h.indexOf(':');
            if (colon > 0) {
                String name = h.substring(0, colon).trim();
                String val = h.substring(colon + 1).trim();
                parsedAttackerHeaders.put(name, val);
            }
        }

        List<HarParser.HarEntry> entries = HarParser.parse(harFile);
        if (entries.isEmpty()) {
            System.err.println("[!] No requests found in HAR file: " + harFile.getName());
            return 0;
        }

        System.out.printf("[*] Loaded %d request(s) from %s%n", entries.size(), harFile.getName());
        System.out.printf("[*] Scope restricted to: %s%n", scopeHosts);
        System.out.printf("[*] Rate limit: %.1f req/s | Max requests cap: %d%n", rateLimit, maxRequests);
        if (allowUnsafeMethods) {
            System.out.println("[WARNING] State-changing methods ENABLED (--allow-unsafe-methods flag set)");
        } else {
            System.out.println("[*] Safety default: Replaying only safe methods (GET, HEAD, OPTIONS)");
        }

        HttpReplayer.Config replayerConfig = new HttpReplayer.Config(
                scopeHosts,
                parsedAttackerHeaders,
                !noAnon,
                allowUnsafeMethods,
                rateLimit,
                maxRequests,
                Duration.ofSeconds(10)
        );

        HttpReplayer replayer = new HttpReplayer(replayerConfig);
        List<HttpRequest> reqs = entries.stream().map(HarParser.HarEntry::request).toList();
        List<HttpResponse> resps = entries.stream().map(HarParser.HarEntry::response).toList();

        List<ExchangePair> exchanges = replayer.replayAll(reqs, resps);

        if (exchanges.isEmpty()) {
            System.out.println("[*] No in-scope replay exchanges were performed.");
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
        for (ExchangePair exchange : exchanges) {
            findings.add(classifier.classify(exchange));
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
