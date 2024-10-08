package com.api_gateway.client_service.feature.user_client;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

@FeignClient(name = "user-service", fallback = UserServiceFallback.class)
public interface UserServiceFeignClient {

    @GetMapping("/users/{email}")
    String getUserDetails(@PathVariable("email") String userId);
}

