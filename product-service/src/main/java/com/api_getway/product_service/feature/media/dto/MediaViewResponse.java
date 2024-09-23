package com.api_getway.product_service.feature.media.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import org.springframework.core.io.InputStreamResource;

@Builder
public record MediaViewResponse(

        String fileName,
        @JsonInclude(JsonInclude.Include.NON_NULL)
        String contentType,

        Long fileSize,

        InputStreamResource stream
        ) {
}