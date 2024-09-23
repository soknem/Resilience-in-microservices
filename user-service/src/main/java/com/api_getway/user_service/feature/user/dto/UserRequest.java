package com.api_getway.user_service.feature.user.dto;


import jakarta.validation.constraints.*;
import lombok.Builder;

import java.util.Set;

@Builder
public record UserRequest(


        @NotBlank(message = "Gender is required")
        @Size(max = 10, message = "Gender must be less than or equal to 10 characters")
        String gender
) {
}
