package com.security.auth;

import com.security.auth.dto.LoginResponse;
import com.security.auth.dto.LoginRequest;
import com.security.auth.dto.RegisterRequest;
import com.security.auth.dto.RegisterResponse;
import com.security.jwt.JwtService;
import com.security.user.Role;
import com.security.user.User;
import com.security.user.UserRepo;
import com.security.user.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final UserRepo userRepo;
    private final UserService userService;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

    public ResponseEntity<RegisterResponse> register(RegisterRequest request) {
        if (userRepo.findByUsername(request.getUsername()).isPresent()) {
            return ResponseEntity
                    .status(HttpStatus.CONFLICT)
                    .body(RegisterResponse.builder()
                            .message("User already exists!")
                            .build());
        }

        if (userRepo.findByEmail(request.getEmail()).isPresent()) {
            return ResponseEntity
                    .status(HttpStatus.CONFLICT)
                    .body(RegisterResponse.builder()
                            .message("This email is already being used!")
                            .build());
        }

        var user = User.builder()
                .username(request.getUsername())
                .password(encoder.encode(request.getPassword()))
                .email(request.getEmail())
                .role(Role.USER)
                .build();

        userRepo.save(user);

        return ResponseEntity.ok(
                RegisterResponse.builder()
                        .message("User register successful!")
                        .build()
        );
    }

    public ResponseEntity<LoginResponse> login(LoginRequest request) {
        final String username = request.getUsername();

        var user = userRepo.findByUsername(username).orElse(null);

        if (user == null) {
            return ResponseEntity
                    .status(HttpStatus.NOT_FOUND)
                    .body(LoginResponse.builder()
                            .token(null)
                            .user(null)
                            .message("User not found with username: " + username)
                            .build()
                    );
        }

        final String password = request.getPassword();

        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        username,
                        password
                )
        );

        var jwtToken = jwtService.generateToken(user);

        return ResponseEntity.ok(
                LoginResponse.builder()
                        .token(jwtToken)
                        .message("User login successful!")
                        .user(userService.getUserResponse(user))
                        .build()
        );
    }

}
