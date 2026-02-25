package com.server.backend.token.dto.request;

public record TokenRequest(
        String token,
        String type
) {}
