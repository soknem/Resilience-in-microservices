package com.api_gateway.client_service.config;

import io.github.resilience4j.retry.Retry;
import io.github.resilience4j.retry.RetryRegistry;
import io.github.resilience4j.retry.event.RetryEvent;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class Resilience4jConfig {

    @Bean
    public RetryRegistry retryRegistry() {
        RetryRegistry registry = RetryRegistry.ofDefaults();
        Retry retry = registry.retry("productService");

        retry.getEventPublisher()
                .onRetry(this::logRetryEvent);

        return registry;
    }

    private void logRetryEvent(RetryEvent event) {
        System.out.println("Retry attempt #" + event.getNumberOfRetryAttempts() + " for " + event.getName());
    }
}
