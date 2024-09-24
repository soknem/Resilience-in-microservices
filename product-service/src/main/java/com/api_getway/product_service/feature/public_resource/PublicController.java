package com.api_getway.product_service.feature.public_resource;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api/v1/public")
public class PublicController {

    @GetMapping
//    @PreAuthorize("hasAnyAuthority('SCOPE_openid')")
    public String getPublicResource(){
        return "this is public resource in product service";
    }
}
