package com.server.backend.auth;

import com.server.backend.auth.dto.request.LoginRequest;
import com.server.backend.auth.dto.request.RegisterRequest;
import com.server.backend.auth.dto.response.LoginResponse;
import com.server.backend.auth.dto.response.RegisterResponse;
import com.server.backend.jwt.JwtService;
import com.server.backend.user.User;
import com.server.backend.user.UserRepo;
import com.server.backend.user.UserRole;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final UserRepo userRepo;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    private final PasswordEncoder passwordEncoder;

    public ResponseEntity<RegisterResponse> register(RegisterRequest request) {
        if (request.username().isEmpty() || request.password().isEmpty()) {
            return ResponseEntity.badRequest().body(new RegisterResponse(null));
        }

        if (userRepo.findByUsername(request.username()).isPresent()) {
            return ResponseEntity
                    .status(HttpStatus.CONFLICT)
                    .body(new RegisterResponse("User already exists!"));
        }

        if (userRepo.findByEmail(request.email()).isPresent()) {
            return ResponseEntity
                    .status(HttpStatus.CONFLICT)
                    .body(new RegisterResponse("Email is already taken!"));
        }

        var user = User.builder()
                .username(request.username())
                .password(passwordEncoder.encode(request.password()))
                .email(request.email())
                .role(UserRole.USER)
                .build();

        userRepo.save(user);

        return ResponseEntity.ok(new RegisterResponse("User registered successfully!"));
    }

    public ResponseEntity<LoginResponse>  login(LoginRequest request) {
        if (request.password().isEmpty() || request.username().isEmpty() ) {
            return ResponseEntity
                    .badRequest()
                    .body( new LoginResponse(
                            null,
                            "Invalid username or password"));
        }

        var username = request.username();
        var user = userRepo.findByUsername(username).orElse(null);

        if (user == null) {
            return ResponseEntity
                    .status(HttpStatus.NOT_FOUND)
                    .body( new LoginResponse(
                            null,
                            "User not found!"
                    ));
        }

        var password = request.password();

        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        username,
                        password
                )
        );

        var token = jwtService.generateRefreshToken(user);

        return ResponseEntity.ok(new LoginResponse(
                token,
                "User login successful!"
        ));
    }
}
