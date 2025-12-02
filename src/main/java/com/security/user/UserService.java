package com.security.user;

import com.security.user.dto.UserResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.ArrayList;


@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepo userRepo;

    public List<UserResponse> getUsers() {
        var userList = new ArrayList<UserResponse>();

        for (User user : userRepo.findAll()) {
            userList.add(
                    UserResponse.builder()
                            .username(user.getUsername())
                            .email(user.getEmail())
                            .role(user.getRole().toString())
                            .build()
            );
        }

        return userList;
    }

    public UserResponse getUserResponse(User user) {
        return UserResponse.builder()
                .username(user.getUsername())
                .email(user.getEmail())
                .role(user.getRole().toString())
                .build();
    }
}
