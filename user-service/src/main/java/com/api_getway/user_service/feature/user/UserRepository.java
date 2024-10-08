package com.api_getway.user_service.feature.user;

import com.api_getway.user_service.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User,Long> {


    Optional<User> findByEmail(String email);
}
