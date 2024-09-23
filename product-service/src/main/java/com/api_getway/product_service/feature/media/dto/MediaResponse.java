package com.api_getway.product_service.feature.media.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;

@Builder
public record MediaResponse(
        String name,
        @JsonInclude(JsonInclude.Include.NON_NULL)
        String contentType,
        String extension,
        String uri,
        Long size
) {

}