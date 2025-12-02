package com.security.jwt;

import org.springframework.data.jpa.repository.JpaRepository;

public interface BlackListedTokenRepo extends JpaRepository<BlackListedToken, String> {
    boolean existsByToken(String token);
}
