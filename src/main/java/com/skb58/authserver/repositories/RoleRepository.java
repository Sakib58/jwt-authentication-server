package com.skb58.authserver.repositories;

import com.skb58.authserver.models.ERole;
import com.skb58.authserver.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(ERole name);
}
