package com.api_getway.user_service.feature.user;

import com.api_getway.user_service.feature.user.dto.UserRequest;
import com.api_getway.user_service.feature.user.dto.UserResponse;
import com.api_getway.user_service.feature.user.dto.UserUpdateRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpStatus;
//import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;


@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/users")
public class UserController {


//    private final UserService userService;


    @ResponseStatus(HttpStatus.CREATED)
//    @PreAuthorize("hasAuthority('admin:control')")
    @PostMapping
    public UserResponse createUser(@Valid @RequestBody UserRequest userRequest) {
//        return userService.createUser(userRequest);

        return null;
    }


//    @PreAuthorize("hasAuthority('admin:control')")
    @PatchMapping("/{uuid}")
    public UserResponse updateUser(@PathVariable String uuid, @Valid @RequestBody UserUpdateRequest userRequest) {

//        return userService.updateUser(uuid, userRequest);

        return null;
    }


//    @PreAuthorize("hasAuthority('admin:control')")
    @GetMapping
    public Page<UserResponse> getAllUsers(
            @RequestParam(defaultValue = "0") int pageNumber,
            @RequestParam(defaultValue = "25") int pageSize
    ) {
//        return userService.getAllUsers(pageNumber, pageSize);

        return null;
    }


//    @PreAuthorize("hasAnyAuthority('admin:control')")
    @GetMapping("/{uuid}")
    public UserResponse getUserById(@PathVariable String uuid)
    {
//        return userService.getUserById(uuid);

        return null;
    }


}
