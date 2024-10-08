package com.api_gateway.client_service.feature.client.dto;

public record ProductResponse(

        String id,

        String name,

        String image,

        Double price,

        String description
) {
}
