package com.server.backend.token;

import com.server.backend.jwt.JwtService;
import com.server.backend.token.dto.request.TokenRequest;
import com.server.backend.token.dto.response.TokenResponse;
import com.server.backend.token.dto.response.ValidateTokenResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class TokenService {
    private final UserDetailsService userDetailsService;
    private final JwtService jwtService;

    public ResponseEntity<TokenResponse> refreshToken(TokenRequest request) {

        var token = request.token();

        var userDetails = getUserDetailsFromToken(token);

        if (userDetails == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new TokenResponse(
                            token,
                            "Token is invalid!"
                    ));
        }

        if (!jwtService.isTokenUsernameValid(token, userDetails) && !jwtService.isRefreshToken(token)) {
            return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .body(new TokenResponse(
                            token,
                            "Token is invalid!"));
        }

        if (jwtService.isTokenExpired(token)) {
            var type = request.type().isBlank() ? "refresh" : request.type();

            token = type.equals("access")
                    ? jwtService.generateAccessToken(userDetails)
                    : jwtService.generateRefreshToken(userDetails);
        }

        return ResponseEntity.ok(new TokenResponse(
                token,
                "Token refreshed successful!"
        ));
    }

    public ResponseEntity<ValidateTokenResponse> validateToken(TokenRequest request) {
        var token = request.token();
        var userDetails = getUserDetailsFromToken(token);

        if (userDetails == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ValidateTokenResponse(
                            false,
                            "Token is invalid"
                    ));
        }

        var isTokenValid = jwtService.isTokenValid(token, userDetails);

        return ResponseEntity.ok(new ValidateTokenResponse(
                isTokenValid,
                isTokenValid ? "Token is valid" : "Token is invalid"
        ));
    }

    private UserDetails getUserDetailsFromToken(String token)  {
        if (token.isBlank()) {
            return null;
        }

        if (!jwtService.isRefreshToken(token) && !jwtService.isAccessToken(token)) {
            return null;
        }

        try {
            var username = jwtService.extractUsername(token);
            return userDetailsService.loadUserByUsername(username);
        } catch (Exception e) {
            return null;
        }
    }
}
