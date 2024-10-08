package com.api_gateway.client_service.feature.client;

import com.api_gateway.client_service.feature.client.dto.ProductResponse;
import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequestMapping("/api/v1/clients")
@RestController
@RequiredArgsConstructor
public class ClientController {

    private final ProductService productService;

    @GetMapping("/products/{id}")
    public ProductResponse getProductById(@PathVariable String id) {

        System.out.println("Hello");
        return productService.getProductById(id);
    }

}
