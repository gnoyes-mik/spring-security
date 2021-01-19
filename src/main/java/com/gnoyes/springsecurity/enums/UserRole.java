package com.gnoyes.springsecurity.enums;

import lombok.Getter;

@Getter
public enum UserRole {
    ADMIN("ADMIN"),
    NORMAL_USER("USER");

    private final String role;

    UserRole(final String role){
        this.role = role;
    }
}