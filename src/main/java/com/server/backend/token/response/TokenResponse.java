package com.server.backend.token.response;

public record TokenResponse(
        String token,
        String message
) {}
