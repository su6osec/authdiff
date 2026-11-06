package io.github.authdiff.cli.har;

import io.github.authdiff.core.model.ExchangePair;
import io.github.authdiff.core.model.HttpRequest;
import io.github.authdiff.core.model.HttpResponse;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Matches entries across multiple HAR files (Owner, Attacker, Anonymous) by method and URI path.
 */
public final class HarMatcher {

    private HarMatcher() {}

    public static List<ExchangePair> correlate(
            List<HarParser.HarEntry> ownerEntries,
            List<HarParser.HarEntry> attackerEntries,
            List<HarParser.HarEntry> anonEntries
    ) {
        if (ownerEntries == null || ownerEntries.isEmpty()) {
            return Collections.emptyList();
        }

        Map<String, List<HarParser.HarEntry>> attackerMap = indexByEndpoint(attackerEntries);
        Map<String, List<HarParser.HarEntry>> anonMap = indexByEndpoint(anonEntries);

        List<ExchangePair> pairs = new ArrayList<>();

        for (HarParser.HarEntry owner : ownerEntries) {
            String key = endpointKey(owner.request());

            HarParser.HarEntry attackerMatch = pollMatch(attackerMap, key);
            HarParser.HarEntry anonMatch = pollMatch(anonMap, key);

            if (attackerMatch != null) {
                HttpResponse anonRes = anonMatch != null ? anonMatch.response() : null;
                pairs.add(new ExchangePair(owner.request(), owner.response(), attackerMatch.response(), anonRes));
            }
        }

        return Collections.unmodifiableList(pairs);
    }

    private static Map<String, List<HarParser.HarEntry>> indexByEndpoint(List<HarParser.HarEntry> entries) {
        Map<String, List<HarParser.HarEntry>> map = new HashMap<>();
        if (entries == null) return map;

        for (HarParser.HarEntry entry : entries) {
            String key = endpointKey(entry.request());
            map.computeIfAbsent(key, k -> new ArrayList<>()).add(entry);
        }
        return map;
    }

    private static String endpointKey(HttpRequest req) {
        return req.method().toUpperCase() + " " + req.path();
    }

    private static HarParser.HarEntry pollMatch(Map<String, List<HarParser.HarEntry>> map, String key) {
        List<HarParser.HarEntry> list = map.get(key);
        if (list != null && !list.isEmpty()) {
            return list.remove(0);
        }
        return null;
    }
}
