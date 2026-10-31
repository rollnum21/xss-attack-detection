package com.example.xssdetector.service;

import org.springframework.stereotype.Component;

import java.util.Locale;

@Component
public class InputNormalizer {

    /** Trims outer whitespace and folds case; no decoding or execution is performed. */
    public String normalize(String input) {
        return input.trim().toLowerCase(Locale.ROOT);
    }
}
