package com.api_getway.user_service.base;

import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class BasedError<T> {

    private String code;

    // Detail error for user
    private T description;

}

