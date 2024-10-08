package com.api_getway.user_service.feature.user.dto;



import com.api_getway.user_service.domain.Role;
import lombok.Builder;

import java.time.LocalDate;
import java.util.Set;


@Builder
public record UserResponse(

        String email,

        String password,

        String name,

        Boolean isEnable,

        Set<Role> roles

        ){
}
