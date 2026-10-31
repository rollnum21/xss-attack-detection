# Detection Test Corpus

This small educational corpus documents the context and expected result for representative inputs. Every sample is inert text used only as test data. It is never evaluated by a browser or executed by the application.

| Case | Context | Input | Expected result | Expected rule |
| --- | --- | --- | --- | --- |
| body-script-element | `HTML_BODY` | `<script>alert(1)</script>` | `KNOWN_XSS_PATTERN` | `HTML-BODY-SCRIPT-ELEMENT` |
| body-benign-text | `HTML_BODY` | `Hello, this is normal text.` | `NO_KNOWN_XSS_PATTERN` | None |
| body-benign-markup | `HTML_BODY` | `<p>Welcome, student!</p>` | `NO_KNOWN_XSS_PATTERN` | None |
| attribute-event-handler | `HTML_ATTRIBUTE` | `onerror=alert(1)` | `KNOWN_XSS_PATTERN` | `HTML-ATTRIBUTE-EVENT-HANDLER` |
| attribute-markup-breakout | `HTML_ATTRIBUTE` | `title"><img src=x` | `KNOWN_XSS_PATTERN` | `HTML-ATTRIBUTE-MARKUP-BREAKOUT` |
| url-javascript-scheme | `URL` | `javascript:alert(1)` | `KNOWN_XSS_PATTERN` | `URL-JAVASCRIPT-SCHEME` |
| url-normal-web-address | `URL` | `https://example.org/page` | `NO_KNOWN_XSS_PATTERN` | None |
| javascript-dialog-call | `JAVASCRIPT` | `alert(1)` | `KNOWN_XSS_PATTERN` | `JAVASCRIPT-DIALOG-CALL` |
| context-mismatch | `URL` | `<script>alert(1)</script>` | `NO_KNOWN_XSS_PATTERN` | None |
| blank-input | `HTML_BODY` | (empty string) | `INVALID_INPUT` | None |
| unsupported-context | `CSS` | `Hello` | `INVALID_INPUT` | None |

The automated service and API tests cover these representative categories. This corpus is not comprehensive, and its cases do not establish general detection accuracy. No corpus-derived precision, recall, false-positive rate, or detection rate is currently reported.
