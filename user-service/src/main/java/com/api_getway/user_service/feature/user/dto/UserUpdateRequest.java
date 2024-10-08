package com.api_getway.user_service.feature.user.dto;

import java.util.Set;

public record UserUpdateRequest(

        String email,

        String password,

        String name,

        Boolean isEnable

) {
}
