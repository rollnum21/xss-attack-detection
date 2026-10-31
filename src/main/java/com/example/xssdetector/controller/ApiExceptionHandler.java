package com.example.xssdetector.controller;

import com.example.xssdetector.model.DetectionClassification;
import com.example.xssdetector.model.XssAnalysisResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.List;

@RestControllerAdvice
public class ApiExceptionHandler {

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<XssAnalysisResponse> handleUnreadableRequest(HttpMessageNotReadableException exception) {
        XssAnalysisResponse response = new XssAnalysisResponse(
                false,
                DetectionClassification.INVALID_INPUT,
                null,
                List.of(),
                List.of(),
                "Request body must be valid JSON containing input and a context value; use AUTO to check all supported contexts."
        );
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
    }
}
