package com.server.backend.token.response;

public record ValidateTokenResponse(
        boolean isTokenValid,
        String message
) {}
