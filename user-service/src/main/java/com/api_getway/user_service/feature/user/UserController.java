package com.api_getway.user_service.feature.user;

import com.api_getway.user_service.feature.user.dto.UserRequest;
import com.api_getway.user_service.feature.user.dto.UserResponse;
import com.api_getway.user_service.feature.user.dto.UserUpdateRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpStatus;
//import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;


@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/users")
public class UserController {


    private final UserService userService;


    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasAnyAuthority('SCOPE_openid')")
    @PostMapping
    public void createUser(@Valid @RequestBody UserRequest userRequest) {

        userService.createUser(userRequest);

    }


    @PreAuthorize("hasAnyAuthority('SCOPE_openid')")
    @PatchMapping("/{email}")
    public UserResponse updateUser(@PathVariable String email, @Valid @RequestBody UserUpdateRequest userRequest) {

        return userService.updateUserByEmail(email, userRequest);

    }


    @PreAuthorize("hasAnyAuthority('SCOPE_openid')")
    @GetMapping
    public Page<UserResponse> getAllUsers(
            @RequestParam(defaultValue = "0") int pageNumber,
            @RequestParam(defaultValue = "25") int pageSize
    ) {
        return userService.getAllUser(pageNumber, pageSize);

    }


    @PreAuthorize("hasAnyAuthority('SCOPE_openid')")
    @GetMapping("/{email}")
    public UserResponse getUserById(@PathVariable String email)
    {
        return userService.getUserByEmail(email);

    }


}
