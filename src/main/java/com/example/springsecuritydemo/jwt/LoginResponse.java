package com.example.springsecuritydemo.jwt;

import lombok.Data;

import java.util.List;

@Data
public class LoginResponse {
    private String jwtToken;
    private String username;
    private List<String> roles;
    public LoginResponse(String username, List<String> roles, String jwtToken) {
        this.username = username;
        this.roles = roles;
        this.jwtToken = jwtToken;
    }
}
