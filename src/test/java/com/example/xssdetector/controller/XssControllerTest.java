package com.example.xssdetector.controller;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class XssControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void analyzeReturnsContextualDetectionResult() throws Exception {
        mockMvc.perform(post("/api/analyze")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"input\":\"<script>alert(1)</script>\",\"context\":\"HTML_BODY\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.detected").value(true))
                .andExpect(jsonPath("$.classification").value("KNOWN_XSS_PATTERN"))
                .andExpect(jsonPath("$.context").value("HTML_BODY"))
                .andExpect(jsonPath("$.matchedRules[0].id").value("HTML-BODY-SCRIPT-ELEMENT"))
                .andExpect(jsonPath("$.matchedRules[0].cwe").value("CWE-79"));
    }

    @Test
    void analyzeRejectsBlankInputWithStructuredResult() throws Exception {
        mockMvc.perform(post("/api/analyze")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"input\":\"   \",\"context\":\"HTML_BODY\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.classification").value("INVALID_INPUT"));
    }

    @Test
    void analyzeRejectsMissingContextWithStructuredResult() throws Exception {
        mockMvc.perform(post("/api/analyze")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"input\":\"hello\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.classification").value("INVALID_INPUT"));
    }

    @Test
    void analyzeRejectsUnsupportedContextWithStructuredResult() throws Exception {
        mockMvc.perform(post("/api/analyze")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"input\":\"hello\",\"context\":\"CSS\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.classification").value("INVALID_INPUT"))
                .andExpect(jsonPath("$.context").doesNotExist());
    }
}
