package com.api_getway.user_service.feature.user.dto;

import java.time.LocalDate;

public record UserUpdateRequest(
        String username,
        String gender

) {
}
