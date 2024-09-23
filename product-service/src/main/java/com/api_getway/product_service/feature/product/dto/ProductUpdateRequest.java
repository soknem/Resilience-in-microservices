package com.api_getway.product_service.feature.product.dto;

import jakarta.validation.constraints.Positive;

public record ProductUpdateRequest(

        String name,

        String image,

        @Positive(message = "price is positive")
        Double price,

        String description
) {
}
