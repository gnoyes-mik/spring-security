package com.gnoyes.springsecurity.model.dto;

import lombok.Builder;
import lombok.Getter;

@Getter
public class LoginSuccess {
    String userName;
    String jwtAuthToken;
    String role;
    String message;

    @Builder
    LoginSuccess(String userName, String jwtAuthToken, String message, String role) {
        this.userName = userName;
        this.jwtAuthToken = jwtAuthToken;
        this.message = message;
        this.role = role;
    }
}
