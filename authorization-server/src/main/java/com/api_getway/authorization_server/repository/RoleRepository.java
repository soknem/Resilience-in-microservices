package com.api_getway.authorization_server.repository;


import com.api_getway.authorization_server.domain.Role;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepository extends JpaRepository<Role, Integer> {

    Role findByName(String name);
}
