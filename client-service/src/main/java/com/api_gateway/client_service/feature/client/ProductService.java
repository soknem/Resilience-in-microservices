package com.api_gateway.client_service.feature.client;

import com.api_gateway.client_service.feature.client.dto.ProductResponse;
import com.api_gateway.client_service.feature.product_client.ProductServiceFeignClient;
import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import io.github.resilience4j.retry.annotation.Retry;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class ProductService {


    private final ProductServiceFeignClient productServiceFeignClient;

    @CircuitBreaker(name = "productService",fallbackMethod = "getProductByIdFallBack")
    @Retry(name = "productService",fallbackMethod = "getProductByIdFallBack")
    public ProductResponse getProductById(String id) {
        return productServiceFeignClient.getProductById(id);
    }

    public ProductResponse getProductByIdFallBack(String id, Throwable throwable) {

        return new ProductResponse("1","product1","image",10.2,"description");  // Or return some default response
    }


}
