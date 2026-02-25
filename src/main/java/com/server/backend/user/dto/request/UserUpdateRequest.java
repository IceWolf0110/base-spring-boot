package com.server.backend.user.dto.request;

import com.server.backend.user.UserRole;

public record UserUpdateRequest(
        String email,
        String password
) {}
