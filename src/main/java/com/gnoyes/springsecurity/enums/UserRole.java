package com.gnoyes.springsecurity.enums;

import lombok.Getter;

@Getter
public enum UserRole {
    ADMIN("Admin"),
    NORMAL_USER("User"),
    UNKNOWN("Unknown")
    ;

    private final String role;

    UserRole(final String role){
        this.role = role;
    }
}