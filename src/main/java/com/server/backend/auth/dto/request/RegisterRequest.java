package com.server.backend.auth.dto.request;

public record RegisterRequest(
    String username,
    String email,
    String password
) {}
