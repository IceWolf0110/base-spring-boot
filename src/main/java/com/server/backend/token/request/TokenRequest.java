package com.server.backend.token.request;

public record TokenRequest(
        String token,
        String type
) {}
