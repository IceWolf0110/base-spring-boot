package com.server.backend.token.dto.response;

public record ValidateTokenResponse(
        boolean isTokenValid,
        String message
) {}
