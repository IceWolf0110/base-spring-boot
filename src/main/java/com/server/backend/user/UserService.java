package com.server.backend.user;

import com.server.backend.user.dto.request.UserUpdateRequest;
import com.server.backend.user.dto.response.UserResponse;
import com.server.backend.user.dto.response.UserUpdateResponse;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.List;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepo userRepo;
    private final PasswordEncoder passwordEncoder;

    public ResponseEntity<List<UserResponse>> getUserList(@RequestParam(required = false) UserRole role) {
        var users = userRepo.findAll()
                .stream()
                .filter(user -> role == null || user.getRole() == role)
                .map(this::toUserResponse)
                .toList();

        return ResponseEntity.ok(users);
    }

    public ResponseEntity<UserResponse> getUserById(Long id) {
        var user = userRepo.findById(id).orElse(null);

        if (user == null) {
            return ResponseEntity.notFound().build();
        }

        return ResponseEntity.ok(toUserResponse(user));
    }

    public ResponseEntity<UserResponse> getUserByUsername(String username) {
        var user = userRepo.findByUsername(username).orElse(null);

        if (user == null) {
            return ResponseEntity.notFound().build();
        }

        return ResponseEntity.ok(toUserResponse(user));
    }

    public ResponseEntity<UserResponse> getUserByEmail(String email) {
        var user = userRepo.findByEmail(email).orElse(null);

        if (user == null) {
            return ResponseEntity.notFound().build();
        }

        return ResponseEntity.ok(toUserResponse(user));
    }

    private UserResponse toUserResponse(User user) {
        return new UserResponse(
                user.getUsername(),
                user.getEmail(),
                user.getRole()
        );
    }

    @Transactional
    public ResponseEntity<UserUpdateResponse> updateUser(
            Long id,
            UserUpdateRequest request
    ) {
        var user = userRepo.findById(id).orElse(null);

        if (user == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(new UserUpdateResponse("User not found"));
        }

        var email = request.email();

        if (email != null) {
            email = email.trim();

            if (!email.isBlank()
                    && !email.equals(user.getEmail())) {

                if (userRepo.existsByEmail(email)) {
                    return ResponseEntity.badRequest()
                            .body(new UserUpdateResponse("Email already exists"));
                }

                user.setEmail(email);
            }
        }

        var password = request.password();

        if (password != null && !password.isBlank()) {

            if (passwordEncoder.matches(password, user.getPassword())) {
                return ResponseEntity.badRequest()
                        .body(new UserUpdateResponse("New password must be different"));
            }

            user.setPassword(passwordEncoder.encode(password));
        }

        return ResponseEntity.ok(new UserUpdateResponse(
                "User updated successfully"
        ));
    }
}
