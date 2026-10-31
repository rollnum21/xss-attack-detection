package com.example.xssdetector.service;

import com.example.xssdetector.model.DetectionClassification;
import com.example.xssdetector.model.DetectionRule;
import com.example.xssdetector.model.MatchedRule;
import com.example.xssdetector.model.XssAnalysisResponse;
import com.example.xssdetector.model.XssContext;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

@Service
public class XssDetectionService {

    private static final String OWASP_XSS_PREVENTION =
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html";
    private static final String OWASP_DOM_XSS =
            "https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html";
    private static final List<XssContext> SUPPORTED_CONTEXTS = List.of(XssContext.values());

    private static final List<DetectionRule> RULES = List.of(
            new DetectionRule(
                    "HTML-BODY-SCRIPT-ELEMENT", "Script element",
                    "A script element construct was found in data assigned to an HTML body context.",
                    "Do not insert untrusted content as HTML. Render text with safe DOM APIs or apply context-appropriate output encoding.",
                    "CWE-79", OWASP_XSS_PREVENTION, Set.of(XssContext.HTML_BODY),
                    Pattern.compile("<\\s*/?\\s*script\\b", Pattern.CASE_INSENSITIVE)
            ),
            new DetectionRule(
                    "HTML-BODY-EVENT-HANDLER", "HTML event handler attribute",
                    "An executable event-handler attribute construct was found in HTML body input.",
                    "Avoid inline event handlers and keep untrusted data out of executable attributes. Use safe framework bindings and validate the intended value.",
                    "CWE-79", OWASP_XSS_PREVENTION, Set.of(XssContext.HTML_BODY),
                    Pattern.compile("\\bon[a-z]+\\s*=", Pattern.CASE_INSENSITIVE)
            ),
            new DetectionRule(
                    "HTML-BODY-EMBEDDED-ELEMENT", "Embedded HTML element",
                    "An iframe, object, or embed element construct was found in HTML body input.",
                    "Do not create embedded elements from untrusted strings. Use a strict allowlist and safe DOM construction where embedding is required.",
                    "CWE-79", OWASP_XSS_PREVENTION, Set.of(XssContext.HTML_BODY),
                    Pattern.compile("<\\s*(?:iframe|object|embed)\\b", Pattern.CASE_INSENSITIVE)
            ),
            new DetectionRule(
                    "HTML-ATTRIBUTE-EVENT-HANDLER", "Event handler in HTML attribute input",
                    "An event-handler attribute construct was found in data assigned to an HTML attribute context.",
                    "Keep untrusted data out of event-handler attributes. Use a fixed attribute name and context-appropriate attribute encoding.",
                    "CWE-79", OWASP_XSS_PREVENTION, Set.of(XssContext.HTML_ATTRIBUTE),
                    Pattern.compile("(?:^|[\\s\"'`])on[a-z]+\\s*=", Pattern.CASE_INSENSITIVE)
            ),
            new DetectionRule(
                    "HTML-ATTRIBUTE-MARKUP-BREAKOUT", "HTML attribute markup breakout",
                    "Input contains a quote-and-markup sequence that can break out of an HTML attribute value.",
                    "Encode values for the exact quoted attribute context and avoid concatenating untrusted values into HTML markup.",
                    "CWE-79", OWASP_XSS_PREVENTION, Set.of(XssContext.HTML_ATTRIBUTE),
                    Pattern.compile("[\"'][^\"']*>\\s*<\\s*(?:script|svg|img|iframe)\\b", Pattern.CASE_INSENSITIVE)
            ),
            new DetectionRule(
                    "URL-JAVASCRIPT-SCHEME", "JavaScript URL scheme",
                    "A JavaScript URL scheme was found in data assigned to a URL context.",
                    "Reject scriptable URL schemes. Parse the URL and allow only the schemes required by the application, typically HTTPS.",
                    "CWE-79", OWASP_XSS_PREVENTION, Set.of(XssContext.URL),
                    Pattern.compile("^\\s*(?:javascript|vbscript)\\s*:", Pattern.CASE_INSENSITIVE)
            ),
            new DetectionRule(
                    "URL-HTML-DATA-SCHEME", "HTML data URL scheme",
                    "An HTML data URL scheme was found in data assigned to a URL context.",
                    "Do not accept HTML data URLs as destinations. Allowlist safe URL schemes and validate the parsed URL.",
                    "CWE-79", OWASP_XSS_PREVENTION, Set.of(XssContext.URL),
                    Pattern.compile("^\\s*data\\s*:\\s*text/html", Pattern.CASE_INSENSITIVE)
            ),
            new DetectionRule(
                    "JAVASCRIPT-SCRIPT-ELEMENT-BREAKOUT", "Script element breakout",
                    "A closing script element construct can leave an HTML script block when interpreted in that context.",
                    "Avoid placing untrusted values in executable script blocks. Move data to safe serialization mechanisms and use framework-supported bindings.",
                    "CWE-79", OWASP_DOM_XSS, Set.of(XssContext.JAVASCRIPT),
                    Pattern.compile("<\\s*/\\s*script\\b", Pattern.CASE_INSENSITIVE)
            ),
            new DetectionRule(
                    "JAVASCRIPT-DIALOG-CALL", "JavaScript dialog call",
                    "A direct alert, confirm, or prompt call was found in JavaScript-context input; this is a limited indicator, not proof of exploitability.",
                    "Never evaluate untrusted strings as JavaScript. Keep data separate from code and use safe serialization and framework bindings.",
                    "CWE-79", OWASP_DOM_XSS, Set.of(XssContext.JAVASCRIPT),
                    Pattern.compile("(?:^|[;{}])\\s*(?:alert|confirm|prompt)\\s*\\(", Pattern.CASE_INSENSITIVE)
            )
    );

    private final InputNormalizer inputNormalizer;

    public XssDetectionService(InputNormalizer inputNormalizer) {
        this.inputNormalizer = inputNormalizer;
    }

    public XssAnalysisResponse analyze(String input, String requestedContext) {
        if (input == null || input.isBlank()) {
            return invalid(null, List.of(), "Input must contain at least one non-whitespace character.");
        }

        String normalizedInput = inputNormalizer.normalize(input);
        boolean automatic = "AUTO".equalsIgnoreCase(requestedContext == null ? "" : requestedContext.trim());
        XssContext context = parseContext(requestedContext);
        if (!automatic && context == null) {
            return invalid(null, List.of(), "Context is required and must be AUTO, HTML_BODY, HTML_ATTRIBUTE, URL, or JAVASCRIPT.");
        }

        List<XssContext> contextsToAnalyze = automatic ? SUPPORTED_CONTEXTS : List.of(context);
        List<MatchedRule> matches = new ArrayList<>();
        for (XssContext analyzedContext : contextsToAnalyze) {
            for (DetectionRule rule : RULES) {
                if (rule.matches(analyzedContext, normalizedInput)) {
                    matches.add(rule.toMatchedRule(analyzedContext));
                }
            }
        }

        if (matches.isEmpty()) {
            return new XssAnalysisResponse(
                    false,
                    DetectionClassification.NO_KNOWN_XSS_PATTERN,
                    automatic ? null : context,
                    contextsToAnalyze,
                    List.of(),
                    automatic
                            ? "No implemented rule matched in any supported context. This is not proof that the input is safe."
                            : "None of the currently implemented rules matched in this context. This is not proof that the input is safe."
            );
        }
        return new XssAnalysisResponse(
                true,
                DetectionClassification.KNOWN_XSS_PATTERN,
                automatic ? null : context,
                contextsToAnalyze,
                matches,
                automatic
                        ? "Potential XSS-related construct(s) matched while checking supported contexts. The matched context is listed with each rule. Treat this input as untrusted."
                        : "Potential XSS-related construct(s) matched. Treat this input as untrusted and apply context-appropriate defenses."
        );
    }

    private XssContext parseContext(String requestedContext) {
        if (requestedContext == null || requestedContext.isBlank()) {
            return null;
        }
        try {
            return XssContext.valueOf(requestedContext.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException exception) {
            return null;
        }
    }

    private XssAnalysisResponse invalid(XssContext context, String message) {
        return invalid(context, List.of(), message);
    }

    private XssAnalysisResponse invalid(XssContext context, List<XssContext> analyzedContexts, String message) {
        return new XssAnalysisResponse(false, DetectionClassification.INVALID_INPUT, context, analyzedContexts, List.of(), message);
    }
}
