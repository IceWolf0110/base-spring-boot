package com.server.backend.token;

import com.server.backend.token.dto.request.TokenRequest;
import com.server.backend.token.dto.response.TokenResponse;
import com.server.backend.token.dto.response.ValidateTokenResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/token")
@RequiredArgsConstructor
public class TokenController {
    private final TokenService tokenService;

    @PostMapping("/refresh-token")
    public ResponseEntity<TokenResponse> refreshToken(@RequestBody TokenRequest request) {
        return tokenService.refreshToken(request);
    }

    @PostMapping("/validate-token")
    public ResponseEntity<ValidateTokenResponse> validateToken(@RequestBody TokenRequest request) {
        return tokenService.validateToken(request);
    }
}
