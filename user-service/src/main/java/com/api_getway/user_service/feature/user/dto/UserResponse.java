package com.api_getway.user_service.feature.user.dto;



import lombok.Builder;

import java.time.LocalDate;
import java.util.Set;


@Builder
public record UserResponse(

        String uuid,

        String username,


        String gender

        ){
}
