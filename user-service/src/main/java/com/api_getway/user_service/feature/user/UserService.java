package com.api_getway.user_service.feature.user;

import com.api_getway.user_service.feature.user.dto.UserRequest;
import com.api_getway.user_service.feature.user.dto.UserResponse;
import com.api_getway.user_service.feature.user.dto.UserUpdateRequest;
import org.springframework.data.domain.Page;

public interface UserService {

    void createUser(UserRequest userRequest);

    UserResponse getUserByEmail(String email);

    Page<UserResponse> getAllUser(int pageNumber, int pageSize);

    UserResponse updateUserByEmail(String email, UserUpdateRequest userUpdateRequest);
}
