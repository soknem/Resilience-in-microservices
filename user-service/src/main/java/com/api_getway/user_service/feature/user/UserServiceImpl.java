package com.api_getway.user_service.feature.user;

import com.api_getway.user_service.domain.Role;
import com.api_getway.user_service.domain.User;
import com.api_getway.user_service.feature.role.RoleRepository;
import com.api_getway.user_service.feature.user.dto.UserRequest;
import com.api_getway.user_service.feature.user.dto.UserResponse;
import com.api_getway.user_service.feature.user.dto.UserUpdateRequest;
import com.api_getway.user_service.mapper.UserMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.Set;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {


    private final UserRepository userRepository;

    private final UserMapper userMapper;

    private final RoleRepository roleRepository;


    @Override
    public void createUser(UserRequest userRequest) {

        User user = userMapper.fromUserRequest(userRequest);

        Set<Role> roles = roleRepository.findByNameIn(userRequest.roles());

        user.setIsEnabled(true);

        user.setRoles(roles);

        userRepository.save(user);
    }

    @Override
    public UserResponse getUserByEmail(String email) {

        User user = userRepository.findByEmail(email).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND,
                String.format("user = %s has not been found", email)));

        return userMapper.toUserResponse(user);
    }

    @Override
    public Page<UserResponse> getAllUser(int pageNumber, int pageSize) {

        PageRequest pageRequest = PageRequest.of(pageNumber, pageSize);

        Page<User> userPage = userRepository.findAll(pageRequest);

        return userPage.map(userMapper::toUserResponse);
    }

    @Override
    public UserResponse updateUserByEmail(String email, UserUpdateRequest userUpdateRequest) {

        User user =
                userRepository.findByEmail(email).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND,
                        String.format("user = %s has not been found", email)));

        userMapper.updateUserFromRequest(user, userUpdateRequest);

        userRepository.save(user);

        return userMapper.toUserResponse(user);
    }
}
