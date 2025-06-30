package com.example.demo;

import com.example.demo.service.JwtService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
public class AuthController {

    @Autowired
    private JwtService jwtService;

    // Accepts JSON like: { "username": "amrit", "password": "1234" }
    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody LoginRequest request) {
        System.out.println("== LOGIN ATTEMPT ==");
        System.out.println("Username received: " + request.getUsername());
        System.out.println("Password received: " + request.getPassword());
        // Dummy hardcoded username/password
        if ("amrit".equals(request.getUsername()) && "1234".equals(request.getPassword())) {
            String token = jwtService.generateToken(request.getUsername());
            return ResponseEntity.ok(token);
        } else {
            return ResponseEntity.status(401).body("Invalid credentials");
        }
    }
}
