# Cross-Site Scripting (XSS) Attack Detection System

## Project Overview

This is a web-based XSS pattern detection and analysis system. It analyzes user-controlled input with deterministic rules across all supported browser contexts, without asking the user to choose one. A match means a supported construct was recognized; the project does not claim to detect every possible XSS vulnerability.

## Problem Statement

Web applications frequently process user-controlled input. If that input is improperly handled or interpreted in an executable context, it can lead to Cross-Site Scripting (XSS). This project provides a controlled mechanism for analyzing input for known XSS injection constructs.

## Objectives

- Analyze untrusted user input.
- Identify known XSS injection constructs.
- Perform context-aware analysis.
- Map detected constructs to documented security concepts.
- Provide explainable detection results.
- Associate applicable findings with CWE-79.
- Provide security recommendations.
- Demonstrate safe handling of untrusted input.
- Evaluate the detector using the documented [test corpus](src/test/resources/detection-corpus.md).

## Security Basis and Standards

The rule concepts are informed by these references:

1. [OWASP Cross Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html) describes output handling requirements for HTML, attributes, URLs, and script contexts.
2. [OWASP DOM Based XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html) discusses JavaScript and DOM execution contexts and safe handling of untrusted data.
3. [OWASP XSS Filter Evasion Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html) documents ways input filters may be bypassed, which informs the limits of pattern matching.
4. [MITRE CWE-79](https://cwe.mitre.org/data/definitions/79.html) describes improper neutralization of input during web page generation.

The project patterns are implementation choices based on these documented security concepts. The individual regular expressions are not official OWASP rules, and a match is not proof that an application is exploitable.

## Detection Methodology

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

The web interface asks only for the string. It submits the request in `AUTO` mode, which runs rules for all supported contexts. Each match identifies the context in which its rule matched. The API also retains explicit context mode for clients that know their output context. A plain string cannot reveal with certainty where another application will use it, so an automatic context label is a rule match location, not proof of the application's real output context. Normalization trims outer whitespace and folds case; it does not decode entities, execute input, or attempt complex canonicalization. Matches include a rule identifier, name, explanation, mitigation, CWE association, and security reference.

The system does not use arbitrary numerical risk scores or probability percentages.

## Supported Contexts

- `HTML_BODY` — content interpreted as markup inside an HTML body. Rules cover script elements, event-handler attributes, and selected embedded elements.
- `HTML_ATTRIBUTE` — content inserted into an HTML attribute value. Rules cover event-handler attributes and a limited quote-and-markup breakout pattern.
- `URL` — content used as a URL. Rules cover JavaScript or VBScript schemes and HTML data URLs.
- `JAVASCRIPT` — content interpreted within JavaScript. Rules cover a closing script-element sequence and direct dialog calls as limited indicators.

Context matters because browsers interpret the same characters differently in HTML text, an attribute, a URL, or JavaScript. The interface removes the need for the user to choose: it checks all four supported contexts and labels each matched rule with its context. This scan cannot determine how a separate application will actually use the value. Context-specific output encoding and sanitization remain that application's responsibility.

## Detection Result Semantics

- `KNOWN_XSS_PATTERN` means one or more implemented rules matched. It does not establish that the input is exploitable in a particular application.
- `NO_KNOWN_XSS_PATTERN` means none of the currently implemented rules matched in the contexts that were checked. In `AUTO` mode, all four supported contexts are checked. It does **not** mean that the input is proven safe.
- `INVALID_INPUT` means the request has blank or missing input, a missing or unsupported context, or an unreadable JSON body. The API returns HTTP `400` for this result.

Successful analysis results return HTTP `200`.

## Example Analysis

Example 1:

```text
Input: <script>alert(1)</script>
Mode: automatic scan across all supported contexts
Result: KNOWN_XSS_PATTERN
Matched construct: Script element
Classification: CWE-79
```

Example 2:

```text
Input: javascript:alert(1)
Mode: automatic scan across all supported contexts
Result: KNOWN_XSS_PATTERN
Matched construct: JavaScript URL scheme
```

Example 3:

```text
Input: Hello, this is normal text.
Mode: automatic scan across all supported contexts
Result: NO_KNOWN_XSS_PATTERN
```

The third result only means that this detector's current rules did not match. It does not constitute a universal safety guarantee.

## Architecture

```text
Browser UI (HTML / CSS / JavaScript)
   ↓
POST /api/analyze (JSON)
   ↓
XssController
   ↓
XssDetectionService
   ├── InputNormalizer
   └── Context-specific DetectionRule list
   ↓
XssAnalysisResponse (JSON)
   ↓
Browser UI renders with safe DOM APIs
```

`ApiExceptionHandler` returns the same structured result format for unreadable JSON bodies.

## API Documentation

### `POST /api/analyze`

Request:

```json
{
  "input": "<script>alert(1)</script>",
  "context": "AUTO"
}
```

Successful response (`200 OK`):

```json
{
  "detected": true,
  "classification": "KNOWN_XSS_PATTERN",
  "context": null,
  "analyzedContexts": ["HTML_BODY", "HTML_ATTRIBUTE", "URL", "JAVASCRIPT"],
  "matchedRules": [
    {
      "id": "HTML-BODY-SCRIPT-ELEMENT",
      "name": "Script element",
      "description": "A script element construct was found in data assigned to an HTML body context.",
      "recommendation": "Do not insert untrusted content as HTML. Render text with safe DOM APIs or apply context-appropriate output encoding.",
      "context": "HTML_BODY",
      "cwe": "CWE-79",
      "securityReference": "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
    },
    {
      "id": "JAVASCRIPT-SCRIPT-ELEMENT-BREAKOUT",
      "name": "Script element breakout",
      "description": "A closing script element construct can leave an HTML script block when interpreted in that context.",
      "recommendation": "Avoid placing untrusted values in executable script blocks. Move data to safe serialization mechanisms and use framework-supported bindings.",
      "context": "JAVASCRIPT",
      "cwe": "CWE-79",
      "securityReference": "https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html"
    }
  ],
  "message": "Potential XSS-related construct(s) matched while checking supported contexts. The matched context is listed with each rule. Treat this input as untrusted."
}
```

For automatic scans, `context` is `null` and `analyzedContexts` lists every context that was checked. Each entry in `matchedRules` includes its matching `context`. Explicit-context requests return that selected context and a one-item `analyzedContexts` list. When no rules match, `detected` is `false`, `classification` is `NO_KNOWN_XSS_PATTERN`, and `matchedRules` is empty. Invalid requests return `400 Bad Request` with `classification` set to `INVALID_INPUT`.

## Security Design

- User input is treated as untrusted.
- Submitted input is never executed; the detector only analyzes it as data.
- The frontend displays submitted input and API results with safe DOM APIs such as `textContent` and created text nodes. It does not use `innerHTML` to display untrusted input.
- This system is a detector and analysis tool, not a complete XSS prevention mechanism.
- Context-appropriate output encoding, sanitization, secure framework use, and Content Security Policy remain application responsibilities.
- The interface keeps the latest 10 completed analyses in the current browser's `localStorage`. Clear them from the history panel when they are no longer needed.
- Downloaded JSON reports contain the submitted input and analysis response; handle report files as sensitive data.
- The interface includes a persistent light/dark theme, an elapsed-time summary, rule-specific recommendations, and JSON report export.

## Testing and Evaluation

The automated suite includes service unit tests and Spring MVC API tests. It covers the documented test corpus: known constructs, benign text and HTML-like text, all supported contexts, context-specific behavior, missing or unsupported context, blank input, and structured API results. Test inputs are inert strings and are never executed.

Tests live in `src/test/java`, and their expected cases are documented in `src/test/resources/detection-corpus.md`. The project does not currently calculate precision, recall, false-positive rate, detection rate, or other corpus metrics. Any such metric must be calculated from actual, documented test corpus results; no accuracy percentage is claimed.

Run tests with:

```bash
mvn test
```

## Limitations

- The detector does not guarantee detection of every XSS technique.
- Detection depends on supported contexts and implemented rules.
- Absence of a match does not prove an input is safe.
- XSS exploitability depends on how the input is incorporated into an application.
- This system is not a production Web Application Firewall.
- It does not replace output encoding, sanitization, secure framework usage, or Content Security Policy.
- The rule set has a defined scope and can be extended in future work.

## Future Scope

- Expanded context-specific rules.
- A larger curated XSS test corpus.
- More comprehensive standards-informed rule coverage.
- Additional framework-specific analysis.
- Integration with security testing pipelines.
- Comparison against established WAF rule sets.
- Automated regression testing.

These are possible future improvements and are not currently implemented.

## Technology Stack

- Backend: Java 17 source compatibility, Spring Boot, embedded Tomcat.
- Frontend: HTML, CSS, and vanilla JavaScript.
- Build: Maven.
- Communication: REST API with JSON.
- Detection: deterministic context-aware rules implemented with Java regular expressions.
- Testing: JUnit, AssertJ, Spring Boot Test, and MockMvc.

## Project Structure

```text
.
├── README.md
├── XSS_Attack_Detection_Mini_Project_Specification.md
├── docs/PROJECT_REPORT.md
├── pom.xml
└── src
    ├── main
    │   ├── java/com/example/xssdetector
    │   │   ├── XssDetectorApplication.java
    │   │   ├── controller
    │   │   │   ├── ApiExceptionHandler.java
    │   │   │   └── XssController.java
    │   │   ├── model
    │   │   │   ├── DetectionClassification.java
    │   │   │   ├── DetectionRule.java
    │   │   │   ├── MatchedRule.java
    │   │   │   ├── XssAnalysisRequest.java
    │   │   │   ├── XssAnalysisResponse.java
    │   │   │   └── XssContext.java
    │   │   ├── service
    │   │   │   ├── InputNormalizer.java
    │   │   │   └── XssDetectionService.java
    │   └── resources
    │       ├── application.properties
    │       └── static
    │           ├── app.js
    │           ├── index.html
    │           └── styles.css
    └── test
        ├── java/com/example/xssdetector
        │   ├── controller/XssControllerTest.java
        │   └── service/XssDetectionServiceTest.java
        └── resources/detection-corpus.md
└── target/  (generated by Maven; not source-controlled)
```

## Development Status

The Spring Boot setup, context-aware API, deterministic rule engine, responsive frontend, safe result rendering, documented test corpus, and automated backend tests are implemented. The app was started locally and the built-in script example returned the expected rule match through the browser.

## Run Locally

Start the application:

```bash
mvn spring-boot:run
```

Open `http://localhost:8080` in a browser. The page and API are served by the same Spring Boot application.

Run the automated tests with:

```bash
mvn test
```

## Manual Demonstration

1. From the project directory, start the app with `mvn spring-boot:run`.
2. Open `http://localhost:8080`.
3. Paste or type one sample below, then select **Analyze input**. The page scans all supported contexts automatically.
4. Check the result label, matched construct, matching context, explanation, and submitted text.
5. Select **Clear** before trying another sample. The page treats the samples as text and does not execute them.

| Sample input | Expected result | Expected matched construct and context |
| --- | --- | --- | --- |
| `<script>alert(1)</script>` | `KNOWN_XSS_PATTERN` | Script element · `HTML_BODY`; script breakout · `JAVASCRIPT` |
| `javascript:alert(1)` | `KNOWN_XSS_PATTERN` | JavaScript URL scheme · `URL` |
| `onerror=alert(1)` | `KNOWN_XSS_PATTERN` | Event handler · `HTML_BODY` and `HTML_ATTRIBUTE` |
| `alert(1)` | `KNOWN_XSS_PATTERN` | JavaScript dialog call · `JAVASCRIPT` |
| `Hello, this is normal text.` | `NO_KNOWN_XSS_PATTERN` | None matched in the supported contexts |

The normal-text result means only that no current rule matched. It is not a guarantee that the input is safe in every application or context.

### Send a request directly to the API

With the application running, this command sends a sample for automatic analysis across all supported contexts:

```bash
curl -i -X POST http://localhost:8080/api/analyze \
  -H 'Content-Type: application/json' \
  --data '{"input":"javascript:alert(1)","context":"AUTO"}'
```

Expect HTTP `200` and a JSON response with `classification` set to `KNOWN_XSS_PATTERN` and `matchedRules` containing `URL-JAVASCRIPT-SCHEME` labeled with context `URL`.

To see input validation, send whitespace-only input:

```bash
curl -i -X POST http://localhost:8080/api/analyze \
  -H 'Content-Type: application/json' \
  --data '{"input":"   ","context":"HTML_BODY"}'
```

Expect HTTP `400` and `classification` set to `INVALID_INPUT`.
