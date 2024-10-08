package com.api_getway.user_service.feature.user.dto;


import com.api_getway.user_service.domain.Role;
import jakarta.persistence.FetchType;
import jakarta.persistence.ManyToMany;
import jakarta.validation.constraints.*;
import lombok.Builder;

import java.util.Set;

@Builder
public record UserRequest(

        String email,

        String password,

        String name,

        Set<String> roles
) {
}
