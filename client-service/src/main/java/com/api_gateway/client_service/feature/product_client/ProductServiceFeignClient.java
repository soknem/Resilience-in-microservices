package com.api_gateway.client_service.feature.product_client;

import com.api_gateway.client_service.feature.client.dto.ProductResponse;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.context.annotation.Primary;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

@FeignClient(name = "product-service")
public interface ProductServiceFeignClient {

    @GetMapping("/api/v1/products/{id}")
    ProductResponse getProductById(@PathVariable("id") String id);
}

