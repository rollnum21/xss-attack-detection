package com.example.xssdetector.service;

import com.example.xssdetector.model.XssAnalysisResponse;
import com.example.xssdetector.model.DetectionClassification;
import com.example.xssdetector.model.XssContext;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class XssDetectionServiceTest {

    private final XssDetectionService detectionService = new XssDetectionService(new InputNormalizer());

    @Test
    void testSafeInput() {
        XssAnalysisResponse result = detectionService.analyze("Welcome to the student portal.", "HTML_BODY");

        assertThat(result.detected()).isFalse();
        assertThat(result.classification()).isEqualTo(DetectionClassification.NO_KNOWN_XSS_PATTERN);
        assertThat(result.context()).isEqualTo(XssContext.HTML_BODY);
        assertThat(result.matchedRules()).isEmpty();
    }

    @Test
    void testNormalHtmlLikeTextIsSafe() {
        XssAnalysisResponse result = detectionService.analyze("<p>Welcome, student!</p>", "HTML_BODY");

        assertThat(result.classification()).isEqualTo(DetectionClassification.NO_KNOWN_XSS_PATTERN);
    }

    @Test
    void testScriptPatternDetection() {
        XssAnalysisResponse result = detectionService.analyze("<script>alert(1)</script>", "HTML_BODY");

        assertThat(result.detected()).isTrue();
        assertThat(result.classification()).isEqualTo(DetectionClassification.KNOWN_XSS_PATTERN);
        assertThat(result.matchedRules()).extracting("name").contains("Script element");
        assertThat(result.matchedRules()).allSatisfy(rule -> assertThat(rule.cwe()).isEqualTo("CWE-79"));
    }

    @Test
    void testEventHandlerDetection() {
        XssAnalysisResponse result = detectionService.analyze("onerror=example()", "HTML_ATTRIBUTE");

        assertThat(result.classification()).isEqualTo(DetectionClassification.KNOWN_XSS_PATTERN);
        assertThat(result.matchedRules()).extracting("id").contains("HTML-ATTRIBUTE-EVENT-HANDLER");
    }

    @Test
    void testAttributeMarkupBreakoutDetection() {
        XssAnalysisResponse result = detectionService.analyze("title\"><img src=x", "HTML_ATTRIBUTE");

        assertThat(result.classification()).isEqualTo(DetectionClassification.KNOWN_XSS_PATTERN);
        assertThat(result.matchedRules()).extracting("id").contains("HTML-ATTRIBUTE-MARKUP-BREAKOUT");
    }

    @Test
    void testJavaScriptUrlDetection() {
        XssAnalysisResponse result = detectionService.analyze("javascript:alert(1)", "URL");

        assertThat(result.classification()).isEqualTo(DetectionClassification.KNOWN_XSS_PATTERN);
        assertThat(result.matchedRules()).extracting("name").contains("JavaScript URL scheme");
    }

    @Test
    void normalUrlDoesNotMatchXssRules() {
        XssAnalysisResponse result = detectionService.analyze("https://example.org/page", "URL");

        assertThat(result.classification()).isEqualTo(DetectionClassification.NO_KNOWN_XSS_PATTERN);
        assertThat(result.matchedRules()).isEmpty();
    }

    @Test
    void testEmbeddedElementDetection() {
        XssAnalysisResponse result = detectionService.analyze("<iframe src='example-page'></iframe>", "HTML_BODY");

        assertThat(result.classification()).isEqualTo(DetectionClassification.KNOWN_XSS_PATTERN);
        assertThat(result.matchedRules()).extracting("id").contains("HTML-BODY-EMBEDDED-ELEMENT");
    }

    @Test
    void scriptTextInUrlContextDoesNotUseHtmlBodyRules() {
        XssAnalysisResponse result = detectionService.analyze("<script>alert(1)</script>", "URL");

        assertThat(result.classification()).isEqualTo(DetectionClassification.NO_KNOWN_XSS_PATTERN);
        assertThat(result.matchedRules()).isEmpty();
    }

    @Test
    void multipleRulesCanMatchInOneContext() {
        XssAnalysisResponse result = detectionService.analyze("<script onclick=example()>", "HTML_BODY");

        assertThat(result.classification()).isEqualTo(DetectionClassification.KNOWN_XSS_PATTERN);
        assertThat(result.matchedRules()).extracting("id")
                .containsExactly("HTML-BODY-SCRIPT-ELEMENT", "HTML-BODY-EVENT-HANDLER");
    }

    @Test
    void javascriptContextUsesJavaScriptRules() {
        XssAnalysisResponse result = detectionService.analyze("alert(1)", "JAVASCRIPT");

        assertThat(result.classification()).isEqualTo(DetectionClassification.KNOWN_XSS_PATTERN);
        assertThat(result.matchedRules()).extracting("id").contains("JAVASCRIPT-DIALOG-CALL");
    }

    @Test
    void missingContextIsInvalid() {
        XssAnalysisResponse result = detectionService.analyze("example text", null);

        assertThat(result.classification()).isEqualTo(DetectionClassification.INVALID_INPUT);
        assertThat(result.context()).isNull();
    }

    @Test
    void blankInputIsInvalid() {
        XssAnalysisResponse result = detectionService.analyze("  ", "HTML_BODY");

        assertThat(result.classification()).isEqualTo(DetectionClassification.INVALID_INPUT);
    }
}
