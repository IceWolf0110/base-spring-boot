package com.server.backend.user.dto;

import com.server.backend.user.UserController;
import com.server.backend.user.UserRole;

public record UserResponse(
        String username,
        String email,
        UserRole role
) {}
