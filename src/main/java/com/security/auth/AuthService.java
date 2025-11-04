package com.security.auth;

import com.security.auth.dto.AuthResponse;
import com.security.auth.dto.LoginRequest;
import com.security.auth.dto.RegisterRequest;
import com.security.config.jwt.JwtService;
import com.security.user.Role;
import com.security.user.User;
import com.security.user.UserRepo;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final UserDetailsService userDetailsService;
    private final UserRepo userRepo;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

    public AuthResponse register(RegisterRequest request) {
        if (userRepo.findByUsername(request.getUsername()).isPresent()) {
            return AuthResponse
                    .builder()
                    .token(null)
                    .message("User is already exist!")
                    .build();
        }

        var user = User.builder()
                .username(request.getUsername())
                .password(encoder.encode(request.getPassword()))
                .email(request.getEmail())
                .role(Role.USER)
                .build();

        userRepo.save(user);

        return AuthResponse
                .builder()
                .token(null)
                .message("User register successful!")
                .build();
    }

    public AuthResponse login(LoginRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()
                )
        );

        final String username = request.getUsername();

        var user = userRepo.findByUsername(username)
                .orElseThrow(()
                        -> new UsernameNotFoundException("User not found with username: " + username));

        var jwtToken = jwtService.generateToken(user);

        return AuthResponse
                .builder()
                .token(jwtToken)
                .message("User login successful!")
                .build();
    }
}
