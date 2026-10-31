package com.example.xssdetector.model;

import java.util.Set;
import java.util.regex.Pattern;

/** A deterministic project rule derived from a documented security concept. */
public record DetectionRule(
        String id,
        String name,
        String description,
        String recommendation,
        String cwe,
        String securityReference,
        Set<XssContext> contexts,
        Pattern pattern
) {
    public DetectionRule {
        contexts = Set.copyOf(contexts);
    }

    public boolean matches(XssContext context, String normalizedInput) {
        return contexts.contains(context) && pattern.matcher(normalizedInput).find();
    }

    public MatchedRule toMatchedRule(XssContext matchedContext) {
        return new MatchedRule(id, name, description, recommendation, matchedContext, cwe, securityReference);
    }
}
