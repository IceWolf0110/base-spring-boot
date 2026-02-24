package com.server.backend.auth.dto.response;

public record LoginResponse(
        String refreshToken,
        String message
) {}
