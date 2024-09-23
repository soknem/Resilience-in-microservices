package com.api_getway.product_service.feature.product.dto;

public record ProductResponse(

        String id,

        String name,

        String image,

        Double price,

        String description
) {
}
