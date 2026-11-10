package com.taskflow.ai.service;

import com.taskflow.ai.config.JwtUtils;
import com.taskflow.ai.dto.AuthResponse;
import com.taskflow.ai.dto.LoginRequest;
import com.taskflow.ai.dto.RegisterRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;


@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtils jwtUtils;

    public AuthResponse register(RegisterRequest request){
        if(userRepository.existsByUsername(request.getUsername())){
            throw new RuntimeException("User name is already taken");
        }

        if(userRepository.existsByEmail(request.getEmail())){
            throw new RuntimeException("Email is already registered!");
        }

       User user = User.builder()
               .username(request.getUsername())
               .email(request.getEmail())
               .password(passwordEncoder.encode(request.getPassword()))
               .role(User.Role.ROLE_USER)
               .build();

        userRepository.save(user);

        String token = jwtUtils.generateToken(user.getUsername(), user.getRole().name());
        return new AuthResponse(token, user.getUsername(), user.getRole().name());
    }


    public AuthResponse login(LoginRequest request){
        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new RuntimeException("Invalid username or password"));

        if(!passwordEncoder.matches(request.getPassword(), user.getPassword())){
            throw new RuntimeException("Invalid username or password");
        }

        String token = jwtUtils.generateToken(user.getUsername(), user.getRole().name());
        return new AuthResponse(token, user.getUsername(), user.getRole().name());
    }

}
