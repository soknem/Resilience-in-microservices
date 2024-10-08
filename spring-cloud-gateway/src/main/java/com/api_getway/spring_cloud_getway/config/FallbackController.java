
package com.api_getway.spring_cloud_getway.config;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class FallbackController {

    @GetMapping("/fallback/user")
    public ResponseEntity<String> userServiceFallback() {
        return new ResponseEntity<>("User Service is down. Please try again later.", HttpStatus.SERVICE_UNAVAILABLE);
    }

    @GetMapping("/fallback/product")
    public ResponseEntity<String> productServiceFallback() {
        return new ResponseEntity<>("Product Service is down. Please try again later.", HttpStatus.SERVICE_UNAVAILABLE);
    }

    @GetMapping("/fallback/public")
    public ResponseEntity<String> publicServiceFallback() {
        return new ResponseEntity<>("public Service is down. Please try again later.", HttpStatus.SERVICE_UNAVAILABLE);
    }

    @GetMapping("/fallback/client")
    public ResponseEntity<String> clientServiceFallback() {
        return new ResponseEntity<>("client Service is down. Please try again later.", HttpStatus.SERVICE_UNAVAILABLE);
    }

    @GetMapping("/fallback/authorization")
    public ResponseEntity<String> authorizationServiceFallback() {
        return new ResponseEntity<>("authorization Service is down. Please try again later.", HttpStatus.SERVICE_UNAVAILABLE);
    }
}
