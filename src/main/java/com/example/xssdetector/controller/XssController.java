package com.example.xssdetector.controller;

import com.example.xssdetector.model.XssAnalysisRequest;
import com.example.xssdetector.model.XssAnalysisResponse;
import com.example.xssdetector.model.DetectionClassification;
import com.example.xssdetector.service.XssDetectionService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class XssController {

    private final XssDetectionService detectionService;

    public XssController(XssDetectionService detectionService) {
        this.detectionService = detectionService;
    }

    @PostMapping("/analyze")
    public ResponseEntity<XssAnalysisResponse> analyze(@RequestBody(required = false) XssAnalysisRequest request) {
        XssAnalysisResponse result = request == null
                ? detectionService.analyze(null, null)
                : detectionService.analyze(request.input(), request.context());
        HttpStatus status = result.classification() == DetectionClassification.INVALID_INPUT
                ? HttpStatus.BAD_REQUEST
                : HttpStatus.OK;
        return ResponseEntity.status(status).body(result);
    }
}
