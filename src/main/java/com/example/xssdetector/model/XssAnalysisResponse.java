package com.example.xssdetector.model;

import java.util.List;

public record XssAnalysisResponse(
        boolean detected,
        DetectionClassification classification,
        XssContext context,
        List<XssContext> analyzedContexts,
        List<MatchedRule> matchedRules,
        String message
) {
    public XssAnalysisResponse {
        analyzedContexts = List.copyOf(analyzedContexts);
        matchedRules = List.copyOf(matchedRules);
    }
}
