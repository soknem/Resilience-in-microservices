package com.api_gateway.client_service.feature.client.dto;

import jakarta.validation.constraints.Positive;

public record ProductUpdateRequest(

        String name,

        String image,

        @Positive(message = "price is positive")
        Double price,

        String description
) {
}
