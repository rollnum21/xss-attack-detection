package com.example.xssdetector.model;

public record MatchedRule(
        String id,
        String name,
        String description,
        String recommendation,
        XssContext context,
        String cwe,
        String securityReference
) {
}
