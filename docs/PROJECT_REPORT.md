# Cross-Site Scripting (XSS) Attack Detection System

## Abstract

This project implements a web application that analyzes user-controlled strings for a defined set of Cross-Site Scripting (XSS) related constructs. The interface accepts a string without asking the user to identify a browser context. The deterministic rule engine checks every supported context and labels each match with its rule context, explanation, and security reference. The system treats submitted content as inert data. It is an educational pattern analyzer: a match is not proof of exploitability, and no match is not proof of safety.

## Introduction

Web applications combine data from users with HTML, URLs, and JavaScript. If data is handled in the wrong browser context, the browser may interpret it as markup or executable code. XSS is a class of weakness involving improper neutralization of input during web page generation. Context appropriate output encoding and safe framework usage are central defenses. This project demonstrates how a small analyzer can identify selected constructs and explain why context matters.

## Problem Statement

Web applications frequently process user-controlled input. When that input is improperly handled or interpreted in an executable context, it can contribute to XSS. Developers need to understand that the same characters can be interpreted differently in an HTML body, an attribute, a URL, or JavaScript. This project provides a controlled mechanism for checking input against a documented subset of XSS related constructs.

## Objectives

- Analyze untrusted user input without executing it.
- Identify a defined set of XSS related constructs.
- Check rules across all supported browser contexts automatically.
- Explain matches and associate applicable findings with CWE-79.
- Return a predictable JSON result and practical recommendation.
- Demonstrate safe display of submitted strings in the frontend.
- Evaluate behavior with documented unit and API test cases.

## Scope

The analyzer supports `HTML_BODY`, `HTML_ATTRIBUTE`, `URL`, and `JAVASCRIPT`. Rules identify selected script elements, event handler attributes, embedded HTML elements, attribute breakout sequences, executable URL schemes, HTML data URLs, script element breakouts, and direct JavaScript dialog calls. The implementation uses deterministic Java regular expressions and light normalization.

The project does not parse a complete HTML document, infer where a separate application will place a string, model an application's full output path, decode arbitrary encodings, or guarantee detection of all XSS techniques. It is not a prevention system or production Web Application Firewall.

## Existing System

The project does not benchmark a commercial scanner or web firewall. A pattern match by itself cannot establish how a browser will interpret a value in the application that eventually uses it. The interface avoids requiring users to know the context and checks all supported contexts, while explaining that the results are limited to the current rule set.

## Proposed System

The proposed system includes a browser interface and a Spring Boot REST API. The user submits a string. The backend validates the request, normalizes outer whitespace and case, and in automatic mode checks rules assigned to all four supported contexts. It returns the classification, contexts checked, matched rule contexts, explanations, and recommendations. The frontend presents returned content with safe DOM APIs. API clients may also request one explicit context when they know the intended output location.

The result classifications are:

- `KNOWN_XSS_PATTERN`: at least one implemented rule matched.
- `NO_KNOWN_XSS_PATTERN`: no implemented rule matched in the contexts checked; automatic mode checks all four contexts. This does not prove safety.
- `INVALID_INPUT`: the input or context is missing or invalid, or the JSON request body cannot be read.

## Security Basis

The rule concepts are informed by:

- [OWASP Cross Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [OWASP DOM Based XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)
- [OWASP XSS Filter Evasion Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html)
- [MITRE CWE-79](https://cwe.mitre.org/data/definitions/79.html)

The individual regular expressions are project implementations of selected documented security concepts; they are not official OWASP rules. CWE-79 is an educational association for applicable matches, not a verdict that a particular application is vulnerable.

## Technology Stack

- Frontend: HTML, CSS, and vanilla JavaScript.
- Backend: Java 17 source compatibility and Spring Boot with embedded Tomcat.
- Build: Maven.
- API: REST with JSON.
- Detection: deterministic Java regular expressions selected by context.
- Tests: JUnit, AssertJ, Spring Boot Test, and MockMvc.

## Architecture

```text
Browser UI
   ↓ JSON request
POST /api/analyze
   ↓
XssController
   ↓
XssDetectionService
   ├── InputNormalizer
   └── Context-specific DetectionRule list
   ↓
XssAnalysisResponse
   ↓
Browser UI renders result using safe DOM APIs
```

`ApiExceptionHandler` maps unreadable request bodies to a structured `INVALID_INPUT` response. The API returns HTTP 200 for valid analyses and HTTP 400 for invalid input.

## Methodology

```text
Input
  ↓
Validation
  ↓
Normalization
  ↓
Automatic Scan of Supported Contexts
  ↓
Deterministic Rule Engine
  ↓
Matched Rule(s)
  ↓
Detection Result
  ↓
Explanation + Security Reference
```

Normalization trims leading and trailing whitespace and folds case. It does not decode entities or execute the string. Each rule has an identifier, name, explanation, mitigation recommendation, CWE mapping, reference, supported context, and pattern. The detector does not use arbitrary numerical risk scores or probability percentages.

## Implementation

The frontend is served from Spring Boot's static resources. It provides a text area, example inputs, automatic scanning across supported contexts, an analysis summary, matched-rule context labels and recommendations, browser-local history, JSON report export, and a persistent light/dark theme. The latest 10 completed analyses are stored in browser `localStorage`. Exported reports include the submitted input and should be handled as sensitive data. It uses `textContent` and created text nodes for submitted input and API output and does not use `innerHTML` to display untrusted values.

The backend exposes `POST /api/analyze`. The `input` is required; `context` is `AUTO` for all supported contexts or one explicit context for targeted API use. Responses contain `detected`, `classification`, `context`, `analyzedContexts`, `matchedRules`, and `message`. Automatic mode sets `context` to null and lists all scanned contexts in `analyzedContexts`. Each matched rule contains `id`, `name`, `description`, `recommendation`, its matched `context`, `cwe`, and `securityReference`. No database, authentication, or external scanning service is part of the implementation.

## Testing

The documented case set is in `src/test/resources/detection-corpus.md`. Service unit tests cover benign text, HTML-like text, rules in all four contexts, context mismatch, multiple matches, and invalid input. Spring MVC tests cover structured successful and invalid responses.

The recorded automated run completed with 17 tests: 13 service tests and 4 API tests, with no failures or errors. A manual browser walkthrough also sent script, URL, and benign text examples through the frontend and API and displayed the corresponding results. Test strings were used only as data and were never executed.

## Results

- `<script>alert(1)</script>` matched script-related rules in `HTML_BODY` and `JAVASCRIPT` during automatic analysis and returned `KNOWN_XSS_PATTERN`.
- `javascript:alert(1)` matched the JavaScript URL scheme rule in `URL` during automatic analysis and returned `KNOWN_XSS_PATTERN`.
- `Hello, this is normal text.` returned `NO_KNOWN_XSS_PATTERN` after all supported contexts were checked.
- Blank input and missing or unsupported contexts return `INVALID_INPUT` with HTTP 400.

These results describe the current tests and demonstrations only. The project does not report accuracy percentages or corpus metrics.

## Limitations

- The detector does not guarantee detection of every XSS technique.
- Detection depends on supported contexts and implemented rules. Automatic mode checks all four supported contexts but cannot determine where a separate application will use the string.
- An unmatched string is not proven safe.
- Exploitability depends on the application's output handling and the browser context.
- The system is not a production Web Application Firewall.
- It does not replace context appropriate output encoding, sanitization, secure framework usage, or Content Security Policy.
- The rule set covers a defined subset and may produce false positives and false negatives.

## Future Scope

Possible improvements include expanded context-specific rules, a larger curated test corpus, broader standards-informed rule coverage, framework-specific analysis, integration with security testing pipelines, comparison with established WAF rule sets, and automated regression evaluation. These improvements are not implemented in the current project.

## Conclusion

The project demonstrates a small, explainable method for detecting selected XSS related constructs. The interface checks the supported contexts automatically and identifies which context each matching rule covers. The tool keeps submitted strings inert and communicates the limits of pattern-based analysis. Proper output handling remains the responsibility of the application that uses the input.

## Manual Run Instructions

From the project root, run `mvn spring-boot:run` and open `http://localhost:8080`. Enter a sample and choose **Analyze input**; the interface scans all supported contexts automatically. The README contains examples and direct `curl` requests under **Manual Demonstration**.
