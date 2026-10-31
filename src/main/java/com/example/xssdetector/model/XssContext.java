package com.example.xssdetector.model;

/** Context in which submitted data may be interpreted by a browser. */
public enum XssContext {
    HTML_BODY,
    HTML_ATTRIBUTE,
    URL,
    JAVASCRIPT
}
