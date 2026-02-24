package com.server.backend.user;

import com.server.backend.jwt.JwtService;
import com.server.backend.user.dto.UserResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.List;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepo userRepo;
    private final JwtService jwtService;

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
}
