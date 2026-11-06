package io.github.authdiff.core.model;

/**
 * Access control classification verdict.
 * Every endpoint evaluated by authdiff maps to exactly one Verdict.
 */
public enum Verdict {
    /**
     * User B (different valid authenticated identity) was able to access
     * owner User A's object or resource with successful status and high content similarity.
     */
    LIKELY_IDOR_BOLA("Likely IDOR / BOLA", true),

    /**
     * An unauthenticated request ("anon") was able to access the resource
     * with successful status and content similarity to User A.
     */
    MISSING_AUTHENTICATION("Missing Authentication", true),

    /**
     * Access control held: user B and/or anon received 401/403/404 or a distinctly
     * empty/different/error body.
     */
    ENFORCED("Access Control Enforced", false),

    /**
     * Ambiguous outcome (e.g. 200 with generic error page, redirect to login,
     * very short body, or dynamic error). Authdiff prefers INCONCLUSIVE to a false positive.
     */
    INCONCLUSIVE("Inconclusive", false);

    private final String displayName;
    private final boolean isVulnerability;

    Verdict(String displayName, boolean isVulnerability) {
        this.displayName = displayName;
        this.isVulnerability = isVulnerability;
    }

    public String displayName() {
        return displayName;
    }

    public boolean isVulnerability() {
        return isVulnerability;
    }
}
