package io.github.authdiff.core.detection;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Matches HTTP requests against user-supplied path globs (e.g. "/api/public/**", "GET /health").
 */
public final class PathGlobMatcher {

    private final List<CompiledPattern> patterns = new ArrayList<>();

    public PathGlobMatcher(Collection<String> globPatterns) {
        if (globPatterns != null) {
            for (String glob : globPatterns) {
                if (glob != null && !glob.isBlank()) {
                    patterns.add(compile(glob.trim()));
                }
            }
        }
    }

    public boolean matches(String method, String path) {
        if (path == null) path = "/";
        for (CompiledPattern cp : patterns) {
            if (cp.matches(method, path)) {
                return true;
            }
        }
        return false;
    }

    private static CompiledPattern compile(String glob) {
        String methodFilter = null;
        String pathGlob = glob;

        int firstSpace = glob.indexOf(' ');
        if (firstSpace > 0) {
            methodFilter = glob.substring(0, firstSpace).trim().toUpperCase();
            pathGlob = glob.substring(firstSpace + 1).trim();
        }

        StringBuilder regex = new StringBuilder("^");
        for (int i = 0; i < pathGlob.length(); i++) {
            char c = pathGlob.charAt(i);
            if (c == '*' && i + 1 < pathGlob.length() && pathGlob.charAt(i + 1) == '*') {
                regex.append(".*");
                i++; // skip next '*'
            } else if (c == '*') {
                regex.append("[^/]*");
            } else if (c == '?') {
                regex.append(".");
            } else if ("\\.[]{}()+-^$|".indexOf(c) != -1) {
                regex.append('\\').append(c);
            } else {
                regex.append(c);
            }
        }
        regex.append("$");

        return new CompiledPattern(methodFilter, Pattern.compile(regex.toString()));
    }

    private record CompiledPattern(String methodFilter, Pattern pathPattern) {
        public boolean matches(String method, String path) {
            if (methodFilter != null && !methodFilter.equalsIgnoreCase(method)) {
                return false;
            }
            return pathPattern.matcher(path).matches();
        }
    }
}
