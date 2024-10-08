package com.api_getway.user_service.feature.role;

import com.api_getway.user_service.domain.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.Set;

public interface RoleRepository extends JpaRepository<Role,Long> {

    Set<Role> findByNameIn(Set<String> name);
}
