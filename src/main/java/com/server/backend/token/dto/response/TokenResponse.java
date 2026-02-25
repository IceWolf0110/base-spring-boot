package com.server.backend.token.dto.response;

public record TokenResponse(
        String token,
        String message
) {}
