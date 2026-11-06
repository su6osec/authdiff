package io.github.authdiff.core.detection;

import io.github.authdiff.core.model.AuthDiffFinding;
import io.github.authdiff.core.model.ConfidenceScore;
import io.github.authdiff.core.model.ExchangePair;
import io.github.authdiff.core.model.FindingSignal;
import io.github.authdiff.core.model.HttpRequest;
import io.github.authdiff.core.model.HttpResponse;
import io.github.authdiff.core.model.IdentifierRef;
import io.github.authdiff.core.model.Verdict;
import io.github.authdiff.core.normalize.ResponseNormalizer;
import io.github.authdiff.core.similarity.BodyLengthRatio;
import io.github.authdiff.core.similarity.JsonStructuralComparator;
import io.github.authdiff.core.similarity.TokenSetJaccardSimilarity;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Deterministic authorization classification engine.
 * Maps request exchanges to exactly one Verdict with explainable signals and confidence score.
 */
public final class AuthDiffClassifier {

    public record Options(
            Collection<String> publicAllowlistGlobs,
            double similarityThreshold,
            double highSimilarityThreshold
    ) {
        public static Options defaults() {
            return new Options(Collections.emptyList(), 0.70, 0.85);
        }
    }

    private final Options options;
    private final PathGlobMatcher allowlistMatcher;

    public AuthDiffClassifier() {
        this(Options.defaults());
    }

    public AuthDiffClassifier(Options options) {
        this.options = options != null ? options : Options.defaults();
        this.allowlistMatcher = new PathGlobMatcher(this.options.publicAllowlistGlobs());
    }

    public AuthDiffFinding classify(ExchangePair exchange) {
        HttpRequest req = exchange.ownerRequest();
        HttpResponse ownerRes = exchange.ownerResponse();
        HttpResponse attackerRes = exchange.attackerResponse();
        Optional<HttpResponse> anonRes = exchange.optionalAnonResponse();

        String id = UUID.randomUUID().toString().substring(0, 8);
        String method = req.method();
        String url = req.url();
        String path = req.path();

        List<IdentifierRef> detectedIds = IdentifierDetector.detect(req);
        boolean hasObjectId = !detectedIds.isEmpty();

        List<FindingSignal> signals = new ArrayList<>();

        if (hasObjectId) {
            signals.add(FindingSignal.of(
                    FindingSignal.SignalCategory.OBJECT_IDENTIFIER,
                    "OBJECT_ID_PRESENT",
                    "Detected object identifier(s): " + formatIdentifiers(detectedIds),
                    15
            ));
        }

        // 1. Check user public allowlist
        if (allowlistMatcher.matches(method, path)) {
            signals.add(FindingSignal.of(
                    FindingSignal.SignalCategory.ALLOWLIST,
                    "ALLOWLIST_MATCH",
                    "Path matches user-supplied public endpoint allowlist",
                    -100
            ));
            return createFinding(id, method, url, path, detectedIds, Verdict.ENFORCED,
                    ConfidenceScore.of(100), signals, ownerRes, attackerRes, anonRes, 0.0, Optional.empty(), 0.0,
                    method + " " + path + ": Exempt by user public endpoint allowlist");
        }

        // 2. Check if owner response baseline was valid
        if (!ownerRes.isSuccess()) {
            signals.add(FindingSignal.of(
                    FindingSignal.SignalCategory.STATUS_CODE,
                    "OWNER_BASELINE_FAILED",
                    "Owner response baseline was HTTP " + ownerRes.statusCode() + " (not 2xx)",
                    -50
            ));
            return createFinding(id, method, url, path, detectedIds, Verdict.INCONCLUSIVE,
                    ConfidenceScore.of(30), signals, ownerRes, attackerRes, anonRes, 0.0, Optional.empty(), 0.0,
                    method + " " + path + ": Baseline owner request failed with status " + ownerRes.statusCode());
        }

        // 3. Check traps on attacker response
        if (TrapDetector.isLoginRedirect(attackerRes)) {
            signals.add(FindingSignal.of(
                    FindingSignal.SignalCategory.TRAP_DETECTION,
                    "ATTACKER_LOGIN_REDIRECT",
                    "Attacker received redirect to login: " + attackerRes.headerFirstValue("Location"),
                    -80
            ));
            return createFinding(id, method, url, path, detectedIds, Verdict.ENFORCED,
                    ConfidenceScore.of(95), signals, ownerRes, attackerRes, anonRes, 0.0, Optional.empty(), 0.0,
                    method + " " + path + ": Attacker redirected to login");
        }

        if (TrapDetector.is200WithErrorBody(attackerRes)) {
            signals.add(FindingSignal.of(
                    FindingSignal.SignalCategory.TRAP_DETECTION,
                    "ATTACKER_200_WITH_ERROR_BODY",
                    "Attacker received HTTP 200 with access denied or logical error payload",
                    -80
            ));
            return createFinding(id, method, url, path, detectedIds, Verdict.ENFORCED,
                    ConfidenceScore.of(90), signals, ownerRes, attackerRes, anonRes, 0.0, Optional.empty(), 0.0,
                    method + " " + path + ": Attacker received error body under HTTP 200");
        }

        if (TrapDetector.isSpaShell(attackerRes)) {
            signals.add(FindingSignal.of(
                    FindingSignal.SignalCategory.TRAP_DETECTION,
                    "SPA_SHELL_DETECTED",
                    "Attacker received generic SPA HTML shell, not dynamic API resource",
                    -50
            ));
            return createFinding(id, method, url, path, detectedIds, Verdict.INCONCLUSIVE,
                    ConfidenceScore.of(40), signals, ownerRes, attackerRes, anonRes, 0.0, Optional.empty(), 0.0,
                    method + " " + path + ": Generic SPA HTML shell returned");
        }

        // 4. Check attacker status codes
        if (attackerRes.isAccessDenied()) {
            signals.add(FindingSignal.of(
                    FindingSignal.SignalCategory.STATUS_CODE,
                    "ATTACKER_ACCESS_DENIED",
                    "Attacker received HTTP " + attackerRes.statusCode() + " (Access Denied)",
                    -90
            ));
            return createFinding(id, method, url, path, detectedIds, Verdict.ENFORCED,
                    ConfidenceScore.of(95), signals, ownerRes, attackerRes, anonRes, 0.0, Optional.empty(), 0.0,
                    method + " " + path + ": Enforced with HTTP " + attackerRes.statusCode());
        }

        if (attackerRes.statusCode() == 404 && hasObjectId) {
            signals.add(FindingSignal.of(
                    FindingSignal.SignalCategory.STATUS_CODE,
                    "ATTACKER_NOT_FOUND_ON_OBJECT",
                    "Attacker received HTTP 404 on owner-specific object resource",
                    -75
            ));
            return createFinding(id, method, url, path, detectedIds, Verdict.ENFORCED,
                    ConfidenceScore.of(90), signals, ownerRes, attackerRes, anonRes, 0.0, Optional.empty(), 0.0,
                    method + " " + path + ": Resource not found (404) for secondary identity");
        }

        // 5. Normalize responses and compute similarity
        ResponseNormalizer.NormalizedResponse normOwner = ResponseNormalizer.normalize(ownerRes);
        ResponseNormalizer.NormalizedResponse normAttacker = ResponseNormalizer.normalize(attackerRes);

        double lengthRatio = BodyLengthRatio.compute(normOwner.body(), normAttacker.body());
        double attackerSimilarity = computeSimilarity(normOwner, normAttacker);

        signals.add(FindingSignal.of(
                FindingSignal.SignalCategory.BODY_SIMILARITY,
                "ATTACKER_SIMILARITY_SCORE",
                String.format("Attacker similarity: %.1f%% (length ratio: %.2f)", attackerSimilarity * 100.0, lengthRatio),
                (int) (attackerSimilarity * 40)
        ));

        // 6. Evaluate Anonymous Response (if available)
        Optional<Double> anonSimilarity = Optional.empty();
        Optional<Integer> anonStatus = anonRes.map(HttpResponse::statusCode);
        boolean anonAccessible = false;

        if (anonRes.isPresent()) {
            HttpResponse aRes = anonRes.get();
            if (aRes.isSuccess() && !TrapDetector.is200WithErrorBody(aRes) && !TrapDetector.isLoginRedirect(aRes) && !TrapDetector.isSpaShell(aRes)) {
                ResponseNormalizer.NormalizedResponse normAnon = ResponseNormalizer.normalize(aRes);
                double aSim = computeSimilarity(normOwner, normAnon);
                anonSimilarity = Optional.of(aSim);
                if (aSim >= options.similarityThreshold()) {
                    anonAccessible = true;
                    signals.add(FindingSignal.of(
                            FindingSignal.SignalCategory.ANONYMOUS_BEHAVIOR,
                            "ANON_UNPROTECTED_SUCCESS",
                            String.format("Unauthenticated request succeeded with %.1f%% similarity", aSim * 100.0),
                            40
                    ));
                }
            } else {
                signals.add(FindingSignal.of(
                        FindingSignal.SignalCategory.ANONYMOUS_BEHAVIOR,
                        "ANON_DENIED_OR_REDIRECTED",
                        "Unauthenticated request was denied or redirected (status " + aRes.statusCode() + ")",
                        -20
                ));
            }
        }

        // 7. Heuristic: Check if all responses (Owner, Attacker, Anon) are identical
        boolean allIdentical = false;
        if (anonSimilarity.isPresent()) {
            double aSim = anonSimilarity.get();
            if (attackerSimilarity >= 0.95 && aSim >= 0.95) {
                allIdentical = true;
            }
        }

        if (allIdentical && !hasObjectId) {
            signals.add(FindingSignal.of(
                    FindingSignal.SignalCategory.ALLOWLIST,
                    "ALL_IDENTICAL_NO_OBJECT_ID",
                    "Identical response across all identities on non-object endpoint; indicates public content",
                    -60
            ));
            return createFinding(id, method, url, path, detectedIds, Verdict.INCONCLUSIVE,
                    ConfidenceScore.of(35), signals, ownerRes, attackerRes, anonRes,
                    attackerSimilarity, anonSimilarity, lengthRatio,
                    method + " " + path + ": Identical content across all identities (likely public endpoint)");
        }

        // 8. Decide Missing Authentication
        if (anonAccessible) {
            int score = hasObjectId ? 90 : 65;
            if (anonSimilarity.orElse(0.0) >= options.highSimilarityThreshold()) {
                score += 5;
            }
            Verdict v = Verdict.MISSING_AUTHENTICATION;
            String summary = String.format("%s %s: Unauthenticated access permitted (sim: %.1f%%)",
                    method, path, anonSimilarity.orElse(0.0) * 100.0);
            return createFinding(id, method, url, path, detectedIds, v,
                    ConfidenceScore.of(score), signals, ownerRes, attackerRes, anonRes,
                    attackerSimilarity, anonSimilarity, lengthRatio, summary);
        }

        // 9. Decide IDOR / BOLA vs ENFORCED vs INCONCLUSIVE
        if (attackerRes.isSuccess()) {
            if (attackerSimilarity >= options.similarityThreshold()) {
                if (hasObjectId) {
                    int score = 80;
                    if (attackerSimilarity >= options.highSimilarityThreshold()) {
                        score += 15;
                    }
                    if (lengthRatio >= 0.90) {
                        score += 5;
                    }
                    String idStr = formatIdentifiers(detectedIds);
                    String summary = String.format("%s %s: %s accessible by User B (sim: %.1f%%)",
                            method, path, idStr, attackerSimilarity * 100.0);
                    return createFinding(id, method, url, path, detectedIds, Verdict.LIKELY_IDOR_BOLA,
                            ConfidenceScore.of(score), signals, ownerRes, attackerRes, anonRes,
                            attackerSimilarity, anonSimilarity, lengthRatio, summary);
                } else {
                    // Similar response but no explicit object ID detected
                    int score = 55;
                    String summary = String.format("%s %s: Accessible by User B without explicit object ID in request",
                            method, path);
                    return createFinding(id, method, url, path, detectedIds, Verdict.INCONCLUSIVE,
                            ConfidenceScore.of(score), signals, ownerRes, attackerRes, anonRes,
                            attackerSimilarity, anonSimilarity, lengthRatio, summary);
                }
            } else if (attackerSimilarity < 0.35) {
                // Different content returned for attacker
                signals.add(FindingSignal.of(
                        FindingSignal.SignalCategory.BODY_SIMILARITY,
                        "ATTACKER_CONTENT_DIVERGENT",
                        String.format("Attacker received distinct content (similarity: %.1f%%)", attackerSimilarity * 100.0),
                        -50
                ));
                return createFinding(id, method, url, path, detectedIds, Verdict.ENFORCED,
                        ConfidenceScore.of(75), signals, ownerRes, attackerRes, anonRes,
                        attackerSimilarity, anonSimilarity, lengthRatio,
                        method + " " + path + ": Access control enforced; attacker received isolated content");
            } else {
                // Ambiguous similarity (e.g. 0.35 - 0.70)
                signals.add(FindingSignal.of(
                        FindingSignal.SignalCategory.BODY_SIMILARITY,
                        "AMBIGUOUS_SIMILARITY",
                        String.format("Ambiguous content similarity (%.1f%%)", attackerSimilarity * 100.0),
                        -20
                ));
                return createFinding(id, method, url, path, detectedIds, Verdict.INCONCLUSIVE,
                        ConfidenceScore.of(45), signals, ownerRes, attackerRes, anonRes,
                        attackerSimilarity, anonSimilarity, lengthRatio,
                        method + " " + path + ": Ambiguous response divergence");
            }
        }

        // Fallback
        return createFinding(id, method, url, path, detectedIds, Verdict.INCONCLUSIVE,
                ConfidenceScore.of(40), signals, ownerRes, attackerRes, anonRes,
                attackerSimilarity, anonSimilarity, lengthRatio,
                method + " " + path + ": Inconclusive response status " + attackerRes.statusCode());
    }

    private double computeSimilarity(ResponseNormalizer.NormalizedResponse normA, ResponseNormalizer.NormalizedResponse normB) {
        if (normA.isJson() && normB.isJson()) {
            JsonStructuralComparator.ComparisonResult cmp = JsonStructuralComparator.compare(normA.jsonNode(), normB.jsonNode());
            return cmp.compositeSimilarity();
        }
        return TokenSetJaccardSimilarity.compute(normA.body(), normB.body());
    }

    private String formatIdentifiers(List<IdentifierRef> ids) {
        if (ids == null || ids.isEmpty()) return "none";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < ids.size(); i++) {
            if (i > 0) sb.append(", ");
            sb.append(ids.get(i).humanReadable());
        }
        return sb.toString();
    }

    private AuthDiffFinding createFinding(
            String id,
            String method,
            String url,
            String path,
            List<IdentifierRef> ids,
            Verdict verdict,
            ConfidenceScore confidence,
            List<FindingSignal> signals,
            HttpResponse ownerRes,
            HttpResponse attackerRes,
            Optional<HttpResponse> anonRes,
            double attackerSimilarity,
            Optional<Double> anonSimilarity,
            double attackerLengthRatio,
            String summary
    ) {
        return new AuthDiffFinding(
                id,
                method,
                url,
                path,
                ids,
                verdict,
                confidence,
                signals,
                ownerRes.statusCode(),
                attackerRes.statusCode(),
                anonRes.map(HttpResponse::statusCode),
                attackerSimilarity,
                anonSimilarity,
                attackerLengthRatio,
                summary
        );
    }
}
