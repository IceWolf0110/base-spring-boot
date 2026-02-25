package com.server.backend.user.dto.response;

import com.server.backend.user.UserRole;

public record UserResponse(
        String username,
        String email,
        UserRole role
) {}
