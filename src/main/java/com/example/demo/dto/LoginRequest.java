package com.example.demo.dto;

public class LoginRequest {

    private String username;
    private String password;

    public LoginRequest() {
    }

    public LoginRequest(String username, String password) {
        this.username = username;
        this.password = password;
    }

    // ✅ These are the important ones:
    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    // Optional setters
    public void setUsername(String username) {
        this.username = username;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
