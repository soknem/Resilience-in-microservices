package com.api_gateway.client_service.feature.user_client;

import com.api_gateway.client_service.feature.user_client.UserServiceFeignClient;
import org.springframework.stereotype.Component;

@Component
public class UserServiceFallback implements UserServiceFeignClient {

    @Override
    public String getUserDetails(String userId) {
        return "Fallback response: User service is down or unavailable.";
    }
}
